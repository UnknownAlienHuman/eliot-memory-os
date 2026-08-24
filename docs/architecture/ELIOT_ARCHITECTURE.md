# ELIOT Architecture
## Архитектура намерений, понимания и живучей агентной системы

**Версия:** 4.5-draft
**Дата:** 2026-08-12
**Статус:** кандидат на каноническое принятие
**Нормативная пара:** `ELIOT_ARCHITECTURE.md` + `ELIOT_IMPLEMENTATION.md`

**Переходный режим:** пока новая Implementation не принята, прежние документы сохраняют силу как источники конкретных контрактов существующей системы. При смысловом конфликте развитие новой системы следует этой Architecture; несовместимость фиксируется как migration gap, а не решается скрытым выбором удобного текста.

> **ELIOT нужен, чтобы сменяемые люди и агенты могли сохранять, восстанавливать, проверять и улучшать корректное понимание на длинной траектории работы.**

Понимание не является самоцелью. Оно ценно только тогда, когда помогает выполнить реальную задачу, создать или проверить artifact, принять лучшее решение, пережить сбой и продолжить работу без потери смысла.

ELIOT предполагает, что:

```text
люди и модели ошибаются;
агенты теряют контекст и нарушают инструкции;
данные бывают неверными и отравленными;
инструменты бывают узкими или неправильно настроенными;
модули падают;
правила иногда становятся вреднее ошибки, от которой защищают;
абсолютной полноты знания, истины и надёжности нет.
```

Современные agents также надёжнее работают с ограниченным причинно связным workset, чем с огромным неструктурированным контекстом. Это эмпирическое ограничение текущих cognitive routes, а не вечный закон о размере кода. Поэтому Architecture требует декомпозируемости, минимально достаточного контекста и проверяемых границ, но не задаёт фиксированный размер Module, файла, package или команды агента.

Поэтому ELIOT не строится как безошибочная крепость. Он строится как **живучая когнитивная система**:

```text
цель и контакт с реальностью
→ observations и competing models
→ inquiry, experiment или action
→ artifacts и outcomes
→ comparison, correction и recovery
→ более качественное cognitive inheritance.
```

ELIOT объединяет четыре функции:

```text
Memory OS — сохраняет и развивает когнитивное наследие;
Harness   — связывает задачи, agents, tools, authority и verification;
Smart     — поддерживает понимание, orientation, graphs и Dreamer;
Meta      — наблюдает качество системы, диагностирует drift и превращает outcomes/recovery в Improvement Candidates; bounded repairs выполняет Doctor.
```

Небольшой живучий Kernel удерживает identity, canonical transition boundary, fencing, health и recovery. Он не является вторым интеллектом.

Для рабочего агента смысл ELIOT прост:

```text
решать основную задачу, а не администрировать память;
получать достаточную картину перед существенным решением;
передавать существенные observations, decisions, failures и outcomes;
использовать ELIOT для inquiry, coordination, verification и recovery;
не заявлять certainty или done сильнее имеющегося evidence.
```

Для первого входа достаточно прочитать эту страницу, A1 и A16.3. A0 используется как компас при конфликте; остальные разделы раскрываются по текущей задаче и failure boundary.

---

# A0. Конституционный смысл и правила толкования

## A0.1. Для чего существует Architecture

Architecture — не исполняемый кодекс и не каталог будущих структур. Это **компас решений**. Она фиксирует:

```text
какую проблему решает ELIOT;
какой результат считается ценным;
какие свойства нельзя потерять при смене технологий;
почему выбраны основные принципы;
как действовать при конфликте, отказе и неполном знании;
где Implementation свободна экспериментировать.
```

Architecture нужна прежде всего тогда, когда Implementation сталкивается с выбором. Она должна позволить ответить:

```text
какой вариант лучше сохраняет замысел ELIOT;
какая локальная оптимизация разрушает систему;
какое правило устарело;
где нужен Hard Boundary, а где recovery;
помогает ли механизм человеку и агенту или обслуживает собственную ceremony;
переживёт ли система локальный сбой без потери цели, evidence и управления;
какой дефект требует исправления Architecture, а не нового костыля.
```

Соответствие определяется не количеством выполненных предписаний, а сохранением намерения и наблюдаемого результата.

**ARCH-INTENT-01 — Намерение выше буквального соблюдения.** Правило полезно, пока помогает достигать цели, ради которой введено. Если оно систематически блокирует корректную работу или воспроизводит исходный failure mode, его необходимо оспорить, сузить или изменить открыто.

**Почему:** реальная агентная работа всегда шире заранее написанного правила; буквальная дисциплина без понимания превращает защиту в источник отказа.

**При конфликте:** сохраняются жёсткие границы A0.3; остальное допускает Governed Challenge, обратимое отклонение и проверку результата. Working agent не получает право на скрытый обход только потому, что сослался на Intent: deviation должна быть явной, scoped, находиться в уже выданной authority и иметь owner, review и outcome.

## A0.2. Иерархия архитектурных решений

| Класс | Смысл |
|---|---|
| **Architectural Intent** | Конечная цель и rationale решения; главный ориентир при конфликте |
| **Theory** | Объяснение cognition, memory, resilience и learning; не навязывает единственную механику |
| **Invariant** | Свойство, которое здоровая система сохраняет или восстанавливает на своей траектории |
| **Hard Boundary** | Узкая граница authority, secrets, необратимых effects, proof или canonical integrity; применяется fail-closed |
| **Contract** | Наблюдаемое обязательство capability; при отказе оно может уменьшиться только явно |
| **Guardrail** | Предпочтительная защита от известного класса ошибок; допускает challenge и scoped deviation |
| **Default** | Текущий предпочтительный механизм; заменяем без изменения Intent |
| **Policy** | Управляемое human-решение по privacy, risk, cost, models и эксплуатации |
| **Experiment** | Обратимая проверка гипотезы с evaluator, stop condition и rollback |
| **Empirical Profile** | Versioned знание о конкретной связке model, harness, tools и workload |
| **Metric** | Измеряет свойство, но не становится целью системы |
| **Example** | Иллюстрация без самостоятельной нормативной силы |

`ARCH-*` — устойчивые **decision anchors**. Они помогают восстановить смысл и построить conformance map, но не должны превращать каждую рабочую boundary в церемонию. Нормативная сила не выводится из слов «должен» или «обязан»: её задают класс, rationale и observable property; перечисленный механизм не становится вечным, если это не Hard Boundary.

Invariant оценивается по траектории. Временная ошибка допустима, если она:

```text
обнаружена;
локализована;
не получила скрытую authority;
оставила evidence;
имеет recovery или честную escalation.
```

## A0.3. Жёсткие границы

Fail-closed требуется только там, где ошибка создаёт необратимый или скрытый захват системы:

```text
скрытое создание или расширение authority;
скрытое изменение конечной цели пользователя;
неотслеживаемый необратимый или внешний effect;
ложное утверждение VERIFIED_COMPLETE или иного proof;
скрытая перезапись provenance/history;
возвращение отозванного influence после restore;
второй неуправляемый canonical owner/write path;
вывод secrets или запрещённых данных за privacy boundary.
```

Остальные ошибки по умолчанию обрабатываются через:

```text
buffering;
isolation;
bounded influence;
branch/snapshot;
retry с новым evidence;
alternative route;
repair;
quarantine;
escalation.
```

Безопасность ELIOT основана не только на том, чтобы не допустить ошибку, но и на том, чтобы пережить её без потери управления.

## A0.4. Разрешение конфликтов

Сначала определяется, затронута ли Hard Boundary. Если да, dependent effect останавливается до явной authority или recovery. Иначе конфликт является источником информации.

| Вопрос | Решающее основание |
|---|---|
| Что произошло | Observation, artifact, evidence и применимый verifier |
| Что это означает | Competing models, causal analysis и Concilium |
| Какова цель и допустимый риск | Уполномоченный человек, при необходимости после clarification |
| Что разрешено сейчас | Authority, WorkScope, privacy/cost policy и фактическая integration capability |
| Как реализовать принцип | Intent и Contract; затем самый простой обратимый механизм |
| Какая модель лучше | Discriminative evidence и practical outcome, не число голосов |
| Что делать при недостатке данных | Сохранить unknown; выбрать probe, reversible trial или safe partial progress |

Порядок выбора среди допустимых решений:

```text
1. сохранить заявленную цель и agency пользователя, не подменяя evidence и Hard Boundaries;
2. повысить корректность и исправляемость понимания;
3. предпочесть наблюдаемый, обратимый и восстанавливаемый путь;
4. сохранить provenance, alternatives и dissent;
5. локализовать blast radius и стоимость;
6. выбрать более простой механизм.
```

## A0.5. Concilium

**Concilium** — управляемое совещание людей, agents, моделей и инструментов. Оно нужно не для голосования, а для поиска ошибок общей картины.

Concilium отделяет observations от interpretations, показывает общую Evidence Lineage и common-mode failures, формулирует сильнейшие возражения и rival predictions, предлагает discriminative tests и provisional options. Решение принимает указанный Main Agent или Human decision owner; dissent и условия пересмотра сохраняются.

**ARCH-CONCIL-01 — Dissent важнее количества согласных.** Надёжность возникает из независимых оснований, отрицательной проверки и реальных outcomes, а не из большинства моделей.

## A0.6. Изменение Architecture

```text
повторяющаяся проблема или новый факт
→ краткое описание нарушенного Intent
→ evidence и alternatives
→ последствия для Implementation и migration
→ решение Architecture Owner
→ изменение основного текста.
```

Конкретные contracts и defaults могут уточняться в Implementation, если сохраняются Intent, Hard Boundaries и observable behavior.

Допускается **Recoverable Deviation**: временное scoped отклонение от Guardrail или Contract, если оно необходимо для полезного прогресса и не пересекает Hard Boundary. Оно имеет owner, причину, affected scope, review condition, rollback и outcome. Успешное отклонение становится evidence для исправления правила; неудачное — negative memory.

Запрещены append-only addenda с неявным precedence и вечные исключения без owner/review.

## A0.7. Основной словарь

| Термин | Определение |
|---|---|
| **Coupled Cognitive System** | Временная связка Human/Agent, model, active context, ELIOT, tools, environment и feedback, внутри которой происходит cognition |
| **Concilium** | Управляемое сопоставление independent evidence, rival models, сильнейших objections и discriminative tests; не голосование за truth |
| **Cognitive Episode** | Текущий процесс интерпретации, inquiry, decision и action; не durable record |
| **Cognitive Inheritance** | Проверяемое внешнее наследие между episodes: observations, evidence, models, commitments, decisions, procedures, failures, unknowns и provenance |
| **Understanding State** | Версионируемое публичное представление понимания WorkScope, задачи, опыта и неизвестностей; substrate реконструкции, а не само переживание понимания |
| **Understanding Competence** | Способность конкретной связки model × harness × tools правильно использовать Understanding State |
| **Task Understanding** | Актуальная модель цели, смысла, состояния, связей, alternatives, unknowns, commitments и результата задачи |
| **Active Understanding View** | Decision-boundary проекция Task Understanding, релевантной памяти, epistemic position, attention, affordances и authority для конкретного route |
| **Current Epistemic Position** | Question-, scope- и time-scoped позиция: observed, supported, assumed, conflicted, stale и unknown |
| **Canonical Memory** | Единственный durable semantic owner cognitive inheritance и history; не reality, не cognition и не единственная интерпретация |
| **Governor** | Единственная application authority над admission, canonical transitions, revisions, context, leases и receipts |
| **Authority** | Ограниченное право выполнить transition или внешний effect; не выводится из content, confidence или model role |
| **Principal** | Аутентифицированный Human, agent или service с явными capability и visibility boundaries |
| **Lease** | Scoped, fenced и отзывная форма временной authority |
| **Receipt** | Неизменяемое подтверждение transition/outcome, его identity, scope и status |
| **ELIOT Kernel** | Живучая минимальная часть Governor: identity, fencing, canonical boundary, health, supervision и recovery entrypoint |
| **Host Supervisor** | Минимальный внешний владелец process lifecycle approved services; выполняет start/stop/bounded restart и approved rollback, но не читает project semantics и не выдаёт authority |
| **WorkScope** | Ограниченная область работы с identity, resources, truth surfaces, authority, privacy и state |
| **State Fence** | Набор generations, revisions, policy и integration state, от которых зависит пригодность view, result или authority |
| **Effective Context Profile** | Эмпирическое знание о том, как конкретный model/harness использует context для task family: length, position, tools, self-history, noise, compaction и recovery |
| **Safe Operating Envelope** | Область workload/context, где route сохраняет заданное качество; не равна nominal context maximum |
| **Common Ground** | Проверяемая совместимость terminology, references, commitments и action consequences между routes/participants |
| **Truth surface** | Источник наблюдения, способный измерить конкретное свойство мира |
| **Verifier** | Зарегистрированный способ проверить ожидаемое свойство в известном scope, версии и среде |
| **Theory Portfolio** | Набор competing scoped models с support, counterevidence, dependencies и revision conditions |
| **Epistemic Fitness** | Пригодность модели по evidence, predictive/practical outcomes, transfer, freshness и scope; не единый confidence score |
| **Source Assurance** | Многомерная оценка identity, provenance, integrity, competence, incentives, independence, privacy и injection risk источника |
| **Independence Profile** | Описание независимости evidence, capture, evaluator, model/provider/harness и conceptual frame; не единый scalar |
| **Influence Dependency Closure** | Derived views, procedures, packets и decisions, чьё текущее influence зависит от source/tool/verifier |
| **Semantic Contamination** | Неверная, манипулятивная или overgeneralized информация при сохранной структуре и lineage |
| **Structural Corruption** | Повреждение canonical integrity, ordering, provenance, storage или authority state |
| **Module** | Заменяемая capability с owner, inputs/outputs, dependencies, health, failure domain и recovery boundary |
| **Micro-module** | Минимальная самостоятельно понимаемая, проверяемая и заменяемая capability с одной причинной ответственностью и одним lifecycle owner; её физическая форма и размер принадлежат Implementation/Empirical Profile |
| **Independent Proof Surface** | Возможность проверить Module за его публичным contract и наблюдаемыми effects без обязательного запуска всей системы; такой proof не равен доказательству продукта |
| **Agent Work Unit** | Ограниченная работа одного agent: одна основная causal property/owner, exact scope, минимально достаточный context, expected artifact/evidence, verifier, budget и stop condition |
| **Product Pulse** | Минимальный реальный end-to-end путь, способный обнаружить, что локально корректные Module changes разрушили общий product outcome |
| **Experimental Contour** | Изолированная, capability-bounded и заменяемая среда для непроверенной capability; конкретная sandbox/process/runtime технология определяется Implementation |
| **Module Registry** | Versioned реестр Modules, dependencies, health, compatibility, failure domains и repair recipes |
| **Tool Definition** | Versioned cognitive input: name, description, schema, defaults, examples, permissions и side-effect semantics |
| **Problem State** | Durable состояние operational, cognitive, integration или data-quality проблемы с evidence, owner и resolution condition |
| **Incident** | Тяжёлый Problem State, затрагивающий integrity, authority, security, critical telemetry или опасный неразрешённый effect |
| **Quarantine** | Обратимая изоляция content, operation или Module от текущего influence/effects с owner и release condition |
| **Governance Profile** | Вектор реальных возможностей observation, enforcement и supervision; не маркетинговая оценка интеграции |
| **Session** | Временная identity-bound связь principal, harness, WorkScope, task, authority и telemetry; её потеря не уничтожает durable work |
| **Task Controller** | Временная ответственность за current plan revision одной задачи; её может нести Main Agent или уполномоченный Human, но она не создаёт factual, policy или architecture authority |
| **Route Continuation State** | Временное provider/harness-bound состояние продолжения одного cognitive route; может помогать resume, но не является knowledge, evidence или transferable authority |
| **Ordering Scope** | Минимальная область, где конфликтующие transitions обязаны быть упорядочены |
| **Coordination Scope** | Объявленное объединение Ordering Scopes для multi-scope transition или saga |
| **Authority Epoch** | Generation активного владельца authority; output старого owner после restart/reassignment считается stale |
| **Durable Job** | Долгая операция с identity, owner, State Fence, checkpoint, budget, cancellation, outcome и receipt |
| **Critical Attention** | Существенная obligation, остающаяся активной до resolution, authorized waiver или supersession |
| **Control Reserve** | Недоступная normal workload capacity для cancellation, fencing, telemetry, attention/problem transitions и recovery |
| **Recovery Directive** | Структурированный ответ при отказе: причина, сохранённое состояние, разрешённый следующий шаг и требуемая authority |
| **Conflict Directive** | Краткое operational view конфликта: observations, rival models, common lineage, unresolved residue, decision owner и useful probe |
| **Recovery View** | Минимальная non-semantic projection health, unavailable guarantees, last-known-good, pending recovery intents и manual entrypoint при отказе normal control path |
| **Operational Recovery State** | Ограниченное non-semantic durable state pending operations, checkpoints, fencing и recovery reconciliation |
| **Dreamer** | Instrumental AI service, запускающий bounded model/agent/swarm jobs для curation, orientation и research synthesis; не owner и не authority |
| **Watchdog** | Независимый supervision daemon для liveness, protocol discipline, security и recovery. Он непрерывно работает внутри заявленного активного интервала ELIOT; вне использования, maintenance и recovery может быть остановлен после сохранения cursors/wake state. Не semantic oracle |
| **Researcher** | Будущий optional Module для acquisition, parsing, indexing и retrieval внешних документов/corpora |
| **Architecture Knowledge** | Точная принятая Architecture, rationale, IDs и change procedure как load-bearing self-knowledge ELIOT |

Словарь содержит только сквозные load-bearing понятия. Локальный термин определяется один раз в своём разделе и не создаёт параллельную ontology.

## A0.8. Progressive conformance

ELIOT развивается слоями. До заявления durable/recoverable работы нужны:

```text
один canonical history/write path;
provenance, scope, authority и receipt для значимых transitions;
forward revision и проверяемый recovery entrypoint;
различие observation, interpretation, unknown и verified result;
запрет ложного done и скрытой деградации;
bounded resources и actionable failure.
```

Первый полезный vertical spine:

```text
один реальный agent bridge;
естественный capture observations без знания ontology;
один WorkScope и task state;
basic Active Understanding View;
хотя бы один world/task event, реактивно доставляющий relevant memory или obligation;
один truth/verifier route;
честный finish outcome;
минимальный supervision/restart;
Problem/notification path для agent и Human.
```

Basic supervision входит в первый spine. Basic Dreamer Orientation является первой Smart-глубиной после надёжного capture/retrieval loop; advanced security audit, research, graphs, large swarm, recovery depth и Meta experiments добавляются позже. Когда WorkScope — сам ELIOT, применимая Architecture Knowledge входит уже в basic Active Understanding View. Отсутствующая capability маркируется честно и не блокирует независимую ценность.

Vertical spine является первым полезным срезом, а не полным ELIOT. Полное соответствие означает, что Memory OS, Harness, Smart и Meta образуют замкнутый наблюдаемый loop на заявленном Governance Profile; отсутствующие capabilities и гарантии видимы. Соответствие подтверждается живой conformance map A6.7, а не количеством формально выполненных пунктов.

**ARCH-DEV-01 — Working system before broad hardening.** Сначала создаётся реальный end-to-end cognitive loop; тесты и глубина добавляются по наблюдаемым failure modes.

## A0.9. Текущие стратегические defaults

ELIOT создаётся как local-first система для массовых пользователей настольных компьютеров, преимущественно Windows.

Текущая стратегия:

| Default | Почему выбран |
|---|---|
| Rust для daemon/control plane | Memory safety, предсказуемая native concurrency, низкий overhead и пригодность для долгоживущего локального service |
| Hybrid canonical storage типа SurrealDB | Graph, document, temporal и structured state нужны под одним governed owner, а не в наборе расходящихся stores |
| Windows-first эксплуатация | Основные пользователи и agent tools работают на Windows; local-first продукт должен быть нормальным сервисом именно там |
| Models, agents и tools разных vendors | Capability contracts уменьшают lock-in и позволяют менять cognitive/failure profile без переписывания ELIOT |

Это Defaults, а не вечные Invariants. Замена допустима при сохранении Architecture, migration path и доказанном эксплуатационном выигрыше. Микромодульность, isolation, staged promotion и hot-path discipline являются архитектурными свойствами; конкретные language packages, sandbox/component runtimes и process technologies являются только текущим отображением в Implementation.

---

# A1. Миссия и теоретическое ядро

## A1.1. Главная задача

ELIOT поддерживает **непрерывное корректируемое понимание** между сменяемыми людьми, моделями, agents и sessions.

Понимание — не сохранённый текст и не context packet. Оно проявляется в способности:

```text
определить, что существует и что это означает;
восстановить цель, границы и текущую ситуацию;
увидеть связи, dynamics и причинные alternatives;
различить evidence, hypothesis, unknown и norm;
предсказать последствия вмешательства;
выбрать inquiry или action;
проверить результат и изменить модель.
```

ELIOT сохраняет публичные материалы и организацию для такого понимания. Актуальное cognition возникает в coupled activity.

**ARCH-CORE-01 — Understanding continuity first.** Все органы ELIOT подчинены сохранению, восстановлению и коррекции decision-relevant understanding.

## A1.2. Почему это не RAG

```text
RAG:
query → похожие fragments → prompt.

ELIOT:
goal + world contact + cognitive inheritance
→ scoped competing models и current epistemic position
→ inquiry/action under authority
→ real outcome
→ revision, recovery и reusable learning.
```

RAG, embeddings, full-text и graph retrieval могут быть инструментами ELIOT. Они не решают:

```text
неизвестные неизвестности;
текущую применимость старой памяти;
различение observation и interpretation;
причинность и alternatives;
continuity commitments;
authority и finish;
poisoned influence;
обучение по outcome.
```

Если система только ищет chunks и сокращает prompt, более простой RAG дешевле и правильнее.

## A1.3. Основные постулаты

1. Cognition возникает в связке участников, representations, tools и среды.
2. Memory сохраняет cognitive inheritance, а не готовую мысль.
3. Reality внешняя; ELIOT поддерживает только defeasible epistemic positions.
4. Understanding scoped, plural, action-oriented и revisable.
5. Decision-relevant correctness важнее дополнительной compactness.
6. Intent направляет rules; Hard Boundaries защищают только действительно необратимые границы.
7. Ошибки агентов, modules и памяти являются штатными условиями.
8. Knowledge развивается через inquiry, predictions, practical outcomes и revision.
9. Dissent и negative evidence — производительные ресурсы Concilium.
10. Human, model и deterministic tool обладают разными компетенциями и слепыми зонами.
11. Attention и context являются ограниченными causal interventions.
12. Action бывает pragmatic и epistemic.
13. Causal models остаются defeasible и сравниваются по различающим observations.
14. Security предполагает возможность пробития защиты и ограничивает последствия.
15. Resilience сохраняет возможность cognition после disturbance.
16. Model replacement переносит inheritance, но не tacit strategy.
17. Learning имеет разные уровни и не сводится к изменению weights.
18. Forgetting управляет accessibility и influence, не переписывая factual support.
19. ELIOT должен знать свою Architecture, implementation state и limits.
20. ELIOT помогает человеку и агенту, а не превращает их работу в администрирование системы.
21. Глубина добавляется слоями; Kernel и canonical history не переписываются при каждом улучшении.
22. Работа должна декомпозироваться до decision-sufficient worksets, но Architecture не фиксирует универсальный размер Module или context.
23. Непроверенная capability сначала получает ограниченное влияние и независимую replacement boundary; более тесная интеграция зарабатывается evidence.
24. Swarm является durable конвейером bounded attempts, а не общим бесконечным разговором agents.
25. Testing, debugging и recovery являются частью рабочего feedback loop и Meta-learning, а не отдельной церемонией перед release.

## A1.4. Четыре плоскости

```text
Memory OS — evidence, continuity, memory functions, retrieval, revision и forgetting;
Harness — task framing, tools, agents, swarm, authority, verification и finish;
Smart — Understanding State, graphs, inquiry, Context Compiler и Dreamer;
Meta — Watchdog, Doctor, self-model, evaluation, recovery learning и Improvement Candidates.
```

Они образуют один feedback loop. Ни одна плоскость не получает самостоятельной value или final-decision authority.

**ARCH-CORE-02 — Four planes, one governed loop.** Память, orchestration, intelligence и Meta усиливают друг друга, но их полномочия разделены.

## A1.5. Границы

ELIOT не является:

```text
новой базовой моделью;
универсальной СУБД;
заменой host, IDE, terminal или профессионального ПО;
автономным генератором конечных целей;
системой, гарантирующей безошибочность;
непрерывным автономным LLM-loop;
симуляцией мозга;
коллективным субъектом swarm;
источником абсолютной истины.
```

ELIOT — инструментальная система помощи и демократизации сложной агентной работы. Он должен позволить пользователю без большой команды и инфраструктуры получать качество, continuity и контроль, которые иначе требуют зрелой инженерной организации. Автоматическая multi-node репликация канона не является текущей обязанностью; если она появится, несколько физических узлов сохраняют одного логического owner и causal order.

**ARCH-HELP-01 — ELIOT снижает когнитивную и операционную нагрузку.** Внутренняя сложность оправдана только тогда, когда делает работу человека и основного агента проще, надёжнее и продуктивнее.

---

# A2. Участники, authority и модульность

## A2.1. Complementary fallibility

| Участник | Сильная сторона | Типичная ошибка |
|---|---|---|
| Human | Goals, values, context, legitimate authority | Неполное знание, усталость, противоречивые preferences |
| Main Agent | Semantic synthesis, plans, alternatives | Hallucination, framing, context loss, rationalization |
| Deterministic tool | Точное измерение определённого property | Узкая компетенция, неверная настройка, отсутствие смысла |
| Governor | State, authority, lifecycle, receipts | Неполная observability, implementation defect |
| Dreamer | Broad synthesis и hypothesis generation | Smooth false narrative, correlated model bias |
| Watchdog | Independent process/security observation | False positive, incomplete coverage |
| Verifier | Scoped proof | Неверный construct, stale environment, blind spot |

**ARCH-ROLE-01 — Authority разделена по функции.** Observation, interpretation, authorization и verification не должны без необходимости принадлежать одному участнику.

**ARCH-ROLE-02 — Responsibility следует компетенции и типу ошибки.** Ни Human, ни model, ни tool не являются универсальным oracle.

**ARCH-AUTH-01 — Authority explicit, scoped and fenced.** Ни content, ни model confidence, ни название роли не создают право на transition или effect; authority имеет owner, scope, State Fence и отзыв.

## A2.2. Роли

Описание роли задаёт функцию, а не неявное разрешение. Любое изменение state/effect требует применимой authority. Она может быть заранее делегирована role, work item, policy или lease и проверяться автоматически; отдельная ceremony нужна только у границы impact, uncertainty или delegation. Всё, что не покрыто authority, считается запрещённым. Общая деградация ролей и services определяется A13.11, а не скрытыми исключениями в этом разделе.

### Human roles

- **Requester / Domain Owner** задаёт goal, values, constraints и acceptance.
- **Architecture Owner** принимает изменения Architecture.
- **System Owner** управляет installation, credentials, model routes и system delegation.
- **WorkScope Owner** определяет local policies, protected resources и accepted verifiers.
- **Approver** разрешает точное Critical action.
- **Recovery Principal** выполняет узкий break-glass transition.

Один человек может совмещать роли, но authority не сливается автоматически.

### Main Agent

Интерпретирует смысл, строит competing models, выбирает inquiry/action и предлагает decisions. Не создаёт собственную verification authority, policy или factual proof.

### Task Controller

Владеет current plan revision и coordination одной задачи на действующем Authority Epoch. Обычно эту ответственность несёт Main Agent; Human может принять её явно. Task Controller не владеет factual truth, Architecture или общесистемной policy.

### Governor и Kernel

Governor — единственный application owner canonical transitions, authority, task state, context compilation и receipts. Kernel — его минимальная живучая часть, а не второй Governor.

### Canonical Memory

Сохраняет cognitive inheritance и history. Не является agent, truth или policy owner.

### Truth surfaces и Verifiers

Truth surface даёт observation о конкретном свойстве. Verifier проверяет ожидаемое property в известном scope. Они не определяют цель и не доказывают больше своего Evaluation Contract.

### Harness и Agent Coordinator

Harness связывает model, host, tools и Governor. Agent Coordinator управляет durable work graph, sessions, budgets, leases и aggregation. Они не принимают substantive решение.

### Host Supervisor

Находится вне общего process failure domain основных services. Выполняет только start, stop, bounded restart и approved rollback; не читает project semantics, не формирует diagnosis и не выдаёт canonical authority.

### Watchdog и Doctor

Watchdog независимо наблюдает liveness, protocol discipline, security и integrity. Doctor диагностирует modules и выполняет только зарегистрированные bounded repairs.

### Dreamer

Запускает bounded AI jobs для curation, orientation, research и clarification. Он не владеет памятью, policy, truth или final decision.

### Workers, Auditors, Verifier Agents, Synthesis Agents и Curators

Выполняют узкие задачи, возвращают candidate artifacts и evidence. Их роль не повышает authority результата.

### Human Control Plane

Показывает canonical state и позволяет человеку задавать decisions, approvals, questions Dreamer/Watchdog и recovery actions. Не является вторым owner.

## A2.3. Модульная архитектура

```text
0. Kernel
   identity, authority, fencing, canonical transition boundary,
   control scheduling, health и recovery entrypoint.

1. Canonical state
   Memory OS, tasks, evidence, relations, history, receipts и durable jobs.

2. Instrumental intelligence
   truth adapters, verifiers, code/dependency graphs, logs и artifact inspection.

3. Cognitive intelligence
   Understanding State, Context Compiler, Dreamer, semantic curation и calibration.

4. Harness and orchestration
   agent/tool gateway, swarm, work graph, leases и result aggregation.

5. Surfaces
   agent protocols, Skills, ControlBoardView, Human interface и reports.

External supervision
   Watchdog в отдельном failure domain.
```

Functional layer, source boundary, runtime process и deployment unit — разные измерения. Большое число independently developed Modules не требует такого же числа процессов, services или владельцев state. Kernel поддерживает все четыре функциональные плоскости, но не содержит их глубину. Canonical state обслуживает прежде всего Memory OS и Harness; instrumental/cognitive layers — Smart; Watchdog, Doctor и learning loops — Meta. Kernel владеет логическим lifecycle и fencing Modules; внешний Host Supervisor выполняет physical lifecycle approved generations и остаётся доступен при падении основного процесса.

**Микромодульность** означает, что значимая capability может быть выделена в bounded cell с:

```text
одной причинной ответственностью и одним lifecycle owner;
явным public contract, inputs, outputs и owned mutable state;
allowed effects и authority boundary;
typed dependency ports и one-way dependency direction;
независимой proof surface;
failure, replacement, migration и removal boundary.
```

Micro-module может быть source module, package, sandboxed component, process, service или remote worker. Architecture не предписывает его физическую форму. Внутренняя зависимость значимой capability строится слоями:

```text
contract
→ domain/pure core
→ ports
→ adapters
→ service/lifecycle
→ agent/human surface.
```

Это направление ответственности, а не обязательная структура каталогов. Core не зависит от конкретного vendor, transport, storage, sandbox или UI; adapters не получают права решать task truth, policy или finish.

Architecture не задаёт максимальный размер, количество строк, tokens, files, packages или Modules. Потребность в меньших causal worksets сейчас следует из ограничений model context, parallel agent development и локализации ошибок. Split/merge решается по Effective Context Profile, dependency fan-out, build/test cost, failure isolation, replacement cost и Product Pulse. Улучшение моделей может позволить укрупнение, а наблюдаемый drift — потребовать дополнительного разделения без изменения Architecture.

Новая или существенно изменённая capability сначала работает в наименее привилегированном **Experimental Contour**, достаточном для её функции:

```text
bounded sandboxed component — для чистой и capability-limited логики;
isolated worker — для OS/tool/credential/resource-heavy работы;
integrated runtime generation — только после доказанного выигрыша и тех же conformance/recovery guarantees.
```

Конкретные технологии выбирает Implementation. Ни один contour не является обязательной лестницей зрелости: capability может постоянно оставаться изолированной, если это проще и достаточно производительно. Promotion идёт через contract/conformance, replay, effect-free shadow, bounded canary, active generation, drain/retire или forward rollback. Published generation immutable; активный Module не переписывает себя на месте.

Hot path содержит только bounded, observable и достаточно стабильные operations над совместимым state. Model reasoning, research, compilation, broad indexing, heavy verification и curation выполняются вне synchronous decision boundary и публикуют versioned projections/receipts. Добавление глубины не должно скрыто увеличивать latency или failure domain hot path.

Dependencies бывают required, optional и advisory. Отказ optional Module уменьшает только связанную capability. Hard-dependency graph от Kernel наружу ацикличен. Isolation выбирается по failure semantics: pure cancellable computation может разделять runtime; untrusted, blocking, credential-bearing, resource-heavy или crash-prone capability получает более сильную boundary.

**ARCH-MOD-01 — Small living Kernel.** Падение agent, model route, graph, Dreamer, UI или adapter не должно уничтожать canonical state и независимую работу.

**ARCH-MOD-02 — Depth is additive and micro-modular.** Новая глубина добавляется через independently understandable, testable and replaceable capability cells; их размер и physical form остаются empirical Implementation decisions.

**ARCH-PORT-01 — Органы и execution contours заменяемы.** Models, agents, harnesses, tools, storage, protocols и isolation technologies заменяются через capability, conformance, migration и failure contracts; публичное inheritance переносится, tacit strategy переоценивается.

---

# A3. WorkScope и изменяющийся мир

WorkScope может быть:

```text
Git repository;
обычной directory;
document или media set;
service/runtime;
remote system;
GUI/professional workspace;
research corpus;
composite workflow;
ad hoc task.
```

Git является одним truth surface, а не универсальной identity.

WorkScope содержит:

```text
identity и owners;
resources и external systems;
Terrain;
truth surfaces и verifiers;
privacy/authority boundaries;
current generations и State Fence;
available/missing capabilities;
watchers и change signals.
```

При первом контакте Workspace Bootstrap Scanner строит provisional profile по active roots, files, manifests, services, process state, host capabilities и known integrations. Он не обязан сразу понимать проект полностью.

Изменение resource generation, task revision, policy или integration state инвалидирует только зависимые views, results и leases. Независимое состояние продолжает жить. Expansion, contraction, merge, split или перенос WorkScope являются явными transitions: прежнее evidence не получает новый scope молча, а continuity сохраняется через provenance и revalidation.

Если adapter отсутствует, ELIOT:

```text
ищет другой competent surface;
выполняет direct read или cheap reversible probe;
принимает human observation как observation;
сужает claim/action;
фиксирует unknown и representation gap;
блокирует только зависимый effect.
```

Composite WorkScope не обещает скрытую глобальную атомарность. Cross-scope outcomes остаются явными.

**ARCH-SCOPE-01 — Scope before reuse.** Память, authority и proof используются только в той области и версии, для которой имеют основания.

---
# A4. Cognitive inheritance и память

## A4.1. Что хранит ELIOT

Память ELIOT — не склад текстов, а управляемая история познания и действия.

Функции памяти различаются:

| Функция | Сохраняет |
|---|---|
| Working/continuity | Active bindings, plans, blockers, alternatives, next boundary |
| Episodic | Anchored traces событий, действий и outcomes |
| Semantic | Concepts, propositions, relations и scoped models |
| Procedural | Procedures, Skills, verification и transfer boundaries |
| Prospective | Commitments, deadlines, triggers и deferred intentions |
| Source/epistemic | Provenance, competence, dependence, status и validity |
| Normative/social | Goals, policies, precedents и contested norms |
| Negative | Failures, avoidance, reopen и extinction conditions |

Эти функции могут использовать общий substrate. Разные функции не требуют отдельной базы, но не должны смешиваться семантически.

## A4.2. Capture first, organize later

Рабочий agent сообщает естественным языком и structured observations:

```text
что увидел;
что решил;
что изменил;
что не сработало;
какой outcome получил;
что осталось неизвестным;
что может пригодиться позже.
```

Он не обязан знать внутреннюю ontology, table, relation или lifecycle status.

Governor добавляет доступные metadata: session, task, WorkScope, time, source, touched resources, State Fence, authority и privacy. Если semantic type неясен, material сохраняется как **Observation Candidate**.

ELIOT предпочитает сохранить imperfect observation с provenance, чем потерять его из-за плохой формы.

**ARCH-MEM-01 — Capture first.** Агент решает основную задачу; ELIOT берёт на себя классификацию, linking, curation и lifecycle памяти.

## A4.3. Git-like history и recoverable fallibility

ELIOT допускает неверные observations, hypotheses, summaries и procedures. Semantic error не равна structural corruption.

Принципы истории:

```text
raw source и episode не переписываются молча;
correction создаёт forward revision или supersession;
rival theories могут жить параллельными branches;
merge происходит после evidence и practical tests;
snapshot/backup создаёт recovery point;
ошибка остаётся диагностическим материалом;
privacy erasure является отдельным governed process.
```

Даже poisoned memory может временно попасть в канон как Candidate. Система должна уметь ограничить influence, отозвать dependent representations и восстановиться, не уничтожая forensic history.

**ARCH-MEM-02 — Semantic fallibility is recoverable.** Неверная информация допустима как видимое, versioned и revocable состояние; скрытая перезапись history и provenance недопустима.

## A4.4. Жизненный цикл информации

Единый смысловой поток:

```text
perceive
→ anchor source
→ capture observation
→ classify or retain as candidate
→ reconcile with existing state
→ store/revise
→ bind activation routes
→ retrieve/activate
→ compile Active View
→ use in inquiry/action
→ observe outcome
→ update epistemic position
→ consolidate/reconsolidate
→ adjust accessibility/influence
→ evaluate improvement.
```

Это proof normal form, а не требование синхронно выполнять все стадии для каждого read. Reversible probe может предшествовать полной curation. Material decision должен быть восстановим через применимую часть этой цепи.

Observation не становится verified claim, instruction, procedure, policy или proof только потому, что модель его пересказала, объединила или повторила. Изменение semantic role/status происходит через явный transition с provenance и receipt.

**ARCH-LIFE-01 — No semantic teleportation.** Между observation, interpretation, authority и proof нет скрытых переходов.

## A4.5. Evidence, relations и continuity

Reusable memory имеет хотя бы один observable activation route — world/task cue, commitment, relation или scheduled review. Без него material остаётся cold inheritance, но не отклоняется и не теряется.

Load-bearing record сохраняет:

```text
source и exact anchor;
question/scope/time;
observation или proposition;
epistemic status;
support и counterevidence;
relations и dependencies;
conditions of applicability;
revision/revalidation route;
allowed influence.
```

Relations имеют type, direction, scope, provenance и epistemic status. Similarity, co-change, sequence и graph proximity не создают causality автоматически.

Identity является type-relative. Rename file, restart service или rewrite procedure не всегда создают новый объект; split/merge остаются hypotheses до evidence.

## A4.6. Memory transformation

Summary, merge, episode synthesis, concept formation, procedure synthesis и compaction — не нейтральное форматирование. Они обязаны сохранять:

```text
primary evidence;
lineage;
minority/counterevidence;
uncertainty;
temporal and scope distinctions;
conditions of applicability;
path back to sources.
```

Качество transformation проверяется по coverage, preservation, faithfulness, lineage и reversibility.

**ARCH-MEM-03 — Derived memory не заменяет evidence.** Dreamer, model или deterministic compiler могут создавать полезные representations, но не повышают authority и не уничтожают исходную историю.

## A4.7. Accessibility, support, influence и erasure

Четыре свойства независимы:

```text
существует ли record;
насколько он epistemically supported;
насколько доступен retrieval/attention;
какое влияние ему разрешено.
```

Forgetting управляет accessibility и influence. Belief revision изменяет support. Privacy erasure изменяет physical existence.

Retrieval, citation, repetition и model agreement сами по себе не усиливают memory.

**ARCH-MEM-04 — Retrieval is not reinforcement.** Будущее влияние меняется по outcome-linked evidence, correction или explicit lifecycle decision.

---

# A5. Reality, epistemic position и теории

## A5.1. Reality и observation

Reality не хранится внутри ELIOT. ELIOT хранит ограниченные observations и модели.

Каждый observation имеет две независимые характеристики:

```text
Capture route:
self-reported | harness-observed | independently observed.

Evaluation status:
raw | screened | verifier-backed | contested | stale.
```

Verifier-backed не означает independent. Human observation допустим как observation с provenance, но не автоматически как verification внешнего факта.

## A5.2. Current Epistemic Position

Для конкретного question/scope/time ELIOT показывает:

```text
direct observations;
supported models;
assumptions;
rival models;
conflicts;
stale or superseded positions;
unknowns;
required inquiry.
```

Один canonical owner обеспечивает одну историю transitions, но не одну обязательную интерпретацию.

Fresh observation всегда обновляет evidence state. Он не обязан слепо переписывать устойчивую модель: outlier, transient, sensor error или correlated failure создают conflict и inquiry.

**ARCH-EPI-01 — Reality corrects; positions remain defeasible.** Current Epistemic Position является лучшей обоснованной рабочей моделью, а не внутренним объектом truth.

## A5.3. Theory Portfolio и Epistemic Fitness

В сложном вопросе ELIOT хранит несколько competing models.

Вес theory повышают:

```text
независимое evidence;
верные discriminative predictions;
успешные practical tests;
transfer в новом scope после revalidation;
объяснительная достаточность без лишних assumptions.
```

Вес снижают:

```text
failed prediction;
ошибка downstream artifact или procedure;
counterevidence;
poisoned или dependent lineage;
stale competence/scope;
correlated swarm/evaluator agreement.
```

Практический успех scoped и revocable. Если theory ломает зависимые theories, procedures или artifacts, открывается review, а не dogma.

**ARCH-EPI-02 — Theories earn and lose weight through outcomes.** Knowledge развивается через evidence, prediction, experiment и correction; eloquence, age и votes не создают truth.

## A5.4. Time и State Fence

Для load-bearing state сохраняются:

```text
valid time;
known time;
transaction time;
resource generation;
task, policy и integration revisions.
```

Canonical causal order назначает Governor. External timestamps остаются observations. Lease expiry и local scheduling используют monotonic-compatible clocks; clock anomaly создаёт Problem State и revalidation, а не продлевает authority молча.

State Fence включает только dependencies, способные изменить решение. Изменение unrelated resource не инвалидирует всю задачу.

## A5.5. Verifier и Evaluation Contract

Evaluation Contract определяет:

```text
какое свойство измеряется;
в каком scope/environment/version;
какие inputs и outputs допустимы;
какова uncertainty и freshness;
какие failure modes известны;
что делает result неприменимым.
```

System Owner разрешает installation и credentials. WorkScope Owner принимает применение. Governor связывает verifier с acceptance item и проверяет scope/freshness. Competence доказывается outcomes, а не регистрацией.

Чем выше impact, тем меньше система полагается на self-report исполнителя. Critical result требует route наблюдения/evaluation вне failure domain автора действия, если это практически возможно; иначе finish остаётся честно degraded.

Model evaluator допустим для subjective property, но не является независимым по факту названия модели.

## A5.6. Inquiry и unknown

Unknown — полноценное состояние. Оно содержит:

```text
вопрос;
почему он важен;
какое решение зависит от ответа;
какое observation различит варианты;
самый дешёвый безопасный probe;
условие остановки inquiry.
```

ELIOT различает pragmatic action и epistemic action. Inquiry выбирается по discriminative power, expected information gain, risk, reversibility, cost и opportunity cost.

Корректный результат может быть: «данных недостаточно; самый безопасный полезный следующий шаг — X».

---

# A6. Understanding State и system-level понимание

## A6.1. Что считается пониманием

Decision-adequate understanding отвечает:

```text
что существует;
что это означает и для кого;
зачем существует;
как связано;
как меняется;
почему возникают outcomes;
что известно и неизвестно;
какие alternatives правдоподобны;
какое вмешательство к чему приведёт;
что различит competing explanations.
```

Оно может быть неполным. Дефект — не unknown, а скрытая неизвестность, ложная уверенность или потеря distinctions, способных изменить решение.

## A6.2. Representation, episode и competence

- **Understanding State** — inspectable public representation.
- **Cognitive Episode** — происходящая сейчас интерпретация и действие.
- **Understanding Competence** — способность route построить и применить модель.

Ни storage, ни model отдельно не исчерпывают understanding. Без external state возникает амнезия; без active semantic judgment — организованный архив. Understanding State является governed view и rebuildable projections над Canonical Memory и текущими observations, а не вторым semantic store. WorkScope Understanding scoped; cross-scope System Self-Model хранится отдельно и не переносит project claims автоматически. Route Continuation State может поддерживать продолжение того же route, но hidden reasoning не становится durable knowledge, proof или reward target; ELIOT сохраняет public rationale, evidence и decision state.

**ARCH-UND-01 — Load-bearing understanding имеет публичное выражение.** Решение должно быть восстановимо через evidence, models, alternatives, unknowns и rationale, не через hidden thought.

## A6.3. Слои понимания

```text
goal/value — что требуется и зачем;
semantic — entities, roles и meaning;
structural — boundaries, components и dependencies;
dynamic — states, flows и transitions;
causal — mechanisms, interventions, confounders и counterfactuals;
normative — invariants, policies, commitments и contested norms;
epistemic — evidence, rivals, unknowns и source competence;
historical — decisions, failures, changes и outcomes;
operational — current environment, capabilities и degradation;
metacognitive — coverage, competence, bias и calibration.
```

Meaning не сводится к observed behavior. ELIOT различает intended/declared meaning, institutional role, operational behavior, counterfactual consequences и значение для разных participants. Расхождение между ними является model conflict, а не поводом выбрать один слой молча.

Concept Pyramid является навигационной проекцией:

```text
charter → system map → subsystem capsule → module/workflow card → exact evidence.
```

Она не является самим пониманием и может быть перестроена.

## A6.4. Graphs и artifacts

ELIOT использует несколько графовых плоскостей:

```text
static code/dependency graph;
behavioral/co-change graph;
causal experience graph;
execution/task graph;
artifact-lineage graph;
concept/normative graph.
```

Tools якорят structure; agents интерпретируют смысл; artifacts, tests и outcomes исправляют обе стороны. Ориентация идёт exact-first: known handle/path/symbol/artifact и typed neighborhood предшествуют broad semantic synthesis. Graph index — derived projection, не второй owner.

**ARCH-GROUND-01 — Understanding grounded in tools and artifacts.** Смысловая модель должна быть связана с реальными files, symbols, services, documents, actions и verifiers.

## A6.5. Causality

Causal model хранит:

```text
mechanism;
intervention;
predicted observable;
counterfactual;
possible confounders;
interacting causes;
temporal lag;
abstraction level;
rival explanations;
transfer boundary.
```

Successful outcome подтверждает effect, но не обязательно заявленный mechanism. Causal edge получает status: hypothetical, supported или observed-under-intervention.

Связный narrative сам по себе не доказывает понимание. Causal/operational model получает доверие, когда различает rival explanations, заранее фиксирует observable и выдерживает intervention, verifier или реальный artifact outcome; несовпадение исправляет модель.

**ARCH-UND-02 — Causal understanding is tested by discriminative prediction and outcomes.** Проверяется не красота объяснения, а способность различать варианты, предсказывать последствия и корректироваться по факту.

## A6.6. Correctness и reconstruction cost

Understanding State может быть большим. Active View должен быть ограниченным, но не ценой decision-relevant correctness.

Порядок приоритетов:

```text
reality/evidence fit;
decision sufficiency;
visible uncertainty и alternatives;
timely accessibility/usability;
затем reconstruction cost, latency и token economy.
```

Если понимание не помещается, ELIOT decomposes task, раскрывает primary evidence, создаёт последовательные views или меняет route. Silent loss запрещён.

## A6.7. Self-knowledge ELIOT

Architecture является частью cognitive inheritance. System Self-Model различает:

```text
Constitutional — что ELIOT должен означать;
Implemented — что реально построено;
Operational — что сейчас доступно и деградировано;
Experiential — incidents, repairs и learned limits;
Epistemic — что о себе доказано, оспаривается или неизвестно.
```

Нормативной является точная принятая revision Architecture. Summary, audit, code shape и runtime behavior — projections/evidence, но не источник конституционной authority.

Перед Material изменением самого ELIOT Active View включает применимые principles, rationale, conformance gaps и affected guarantees. Контакт с Module/capability ELIOT активирует связанные Architecture anchors так же, как project cue активирует рабочую memory.

Architecture Knowledge является защищённым primary source. Dreamer briefs, audits, code comments и summaries остаются projections. Живая conformance map связывает Intent/`ARCH-*` с implementation owner, mechanism, failure behavior и observable status; изменение Architecture либо расходящийся runtime инвалидирует зависимые briefs и открывает explicit gap.

Architecture revision digest и conformance state входят в integrity anchors и recovery manifest.

После смены model/harness проверяется **Common Ground**: сохранились ли не только summaries, но и goals, decisions, invariants, rival models, unknowns, commitments и последствия действий. Public inheritance переносится; tacit competence и способ интерпретации требуют requalification.

**ARCH-SELF-01 — ELIOT знает своё назначение и состояние.** Self-model нужен для diagnosis, recovery и improvement, но не даёт системе права самосертифицироваться или менять Architecture.

---

# A7. Attention, context и Skills

## A7.1. Active Understanding View

View компилируется для конкретного `model × task × harness × tools × inference regime`.

Порядок по смыслу:

```text
goal, acceptance и commitments;
blocking attention;
current epistemic position и rivals;
semantic/causal model;
done, open, deferred и killed work;
invariants и negative memory;
unknowns и inquiries;
exact load-bearing evidence;
available/authorized affordances;
next action, expected observable, verifier и stop condition.
```

View использует один применимый State Fence либо явно показывает stale/incompatible sections.

У action boundary формируется короткий **decision-local tail**: current goal, load-bearing position, exact atoms, do-not-use, next action, expected observable, verifier и stop/revision condition. Его layout проверяется по Effective Context Profile, а не фиксируется как вечная prompt-магия.

**ARCH-CTX-01 — Decision sufficiency before size optimization.** Context должен сохранить distinctions, способные изменить решение, risk, verifier или unknowns.

## A7.2. Attention

Selection учитывает:

```text
goal/commitment relevance;
expected decision delta и information gain;
risk, urgency и irreversibility;
prediction error, novelty и surprise;
negative memory и invariants;
minority/counterevidence;
source competence/independence;
opportunity и switching cost;
route-specific usability.
```

Текущий frame может ошибаться. Поэтому high-impact work сохраняет bounded exploration: rival-frame challenge, counterevidence search и coverage-gap review.

## A7.3. Три канала ориентации

### Push

World/task contact активирует связанную memory по file, symbol, error, command, service, document, deadline, commitment или anomaly.

### Pull

Agent знает предмет поиска и запрашивает handles, facts, relations или cases.

### Dreamer Orientation

Goal известен, но скрытые relations и содержимое памяти неизвестны; Dreamer строит bounded problem-oriented packet.

Default:

```text
current task/commitment
→ exact cue/entity/path
→ typed relations
→ bounded retrieval
→ Dreamer synthesis.
```

Retrieval, graph activation и Dreamer search только создают candidates. В Active View они попадают после admission по scope, freshness, provenance, epistemic status, expected decision delta, risk и cost. Причина material inclusion или suppression должна быть восстановима.

**ARCH-CTX-04 — Retrieval proposes; Context Compiler admits.** Найденное не получает influence только потому, что оно похоже или доступно.

**ARCH-CTX-02 — Observable state drives proactive memory.** Полезная memory не должна зависеть только от того, вспомнил ли agent вызвать recall.

На host без event integration push деградирует до обязательной доставки на следующей доступной boundary и видимой obligation; ELIOT не изображает prevention, которого нет.

**ARCH-CTX-03 — Decision locality is route-profiled.** Load-bearing control state располагается там, где конкретный route надёжнее всего использует его у decision boundary; mechanical repetition не увеличивает epistemic support.

## A7.4. Context как intervention

Inclusion, omission, ordering, repetition и schema изменяют inference. Каждый material element имеет роль:

```text
governing instruction;
authoritative state;
evidence;
hypothesis;
prior narrative;
rejected path;
affordance;
untrusted payload.
```

Untrusted content может влиять через priming и framing даже без authority. Поэтому provenance, placement и repetition также governed. Каждое material inclusion или suppression имеет source handle и краткую объяснимую причину; иначе ошибку Context Compiler невозможно диагностировать.

Semantic screening выполняется до hot boundary либо асинхронно. Hot admission, attention и authority gate не ждут LLM: они используют persisted attributes или возвращают bounded inquiry/unknown. Unscreened item доступен как quoted evidence/handle, но не является единственным основанием Critical action.

## A7.5. Critical Attention

Critical Attention — durable obligation, а не сообщение.

Она имеет:

```text
owner;
affected scope/actions;
evidence;
delivery state;
resolution state;
deadline/review condition;
escalation route.
```

Acknowledgement означает получение, но не resolution. Expiry меняет owner/channel, а не удаляет problem.

**ARCH-ATTN-01 — Critical Attention is state, not a message.** Blocking obligation живёт до evidence-backed resolution, authorized waiver или supersession.

## A7.6. Compaction и resume

Compaction — reconstructive transformation. Перед boundary сохраняются:

```text
goal и commitments;
current/rival models;
done, deferred и killed paths;
blockers и exact anchors;
pending verifiers;
next action;
State Fence;
explicit losses.
```

Resume различает:

```text
exact continuation того же route;
reconstruction из public inheritance;
clean reset.
```

Они не эквивалентны. Continuation state не становится knowledge или authority.

## A7.7. Governance Profile

Integration описывается вектором:

```text
Observation: absent | self-reported | host-observed | independently observed;
Enforcement: absent | advisory | interceptable | enforced;
Supervision: absent | self-monitored | watchdog-observed | independently supervised.
```

Policy может свести профиль к grade для конкретного action class, но Architecture не вводит универсальный scalar. Claim не сильнее релевантной weakest axis.

## A7.8. Effective context и внешняя metacognition

Для каждого важного route/task family поддерживается Effective Context Profile и Safe Operating Envelope. Полный dependency set профиля задаётся Capability Registry A11.3; изменение любой load-bearing зависимости делает профиль provisional.

Governor/Watchdog вычисляют внешние признаки:

```text
coverage — где understanding/evidence достаточно, thin или blind;
novelty — насколько task выходит за проверенное inheritance;
danger — hotspots, failures и irreversible boundaries;
calibration — насколько predictions и decisions совпадают с outcomes;
integration confidence — какие observations и enforcement реально доступны.
```

Это не чтение мыслей модели и не единый understanding score.

## A7.9. Context economy

Agent Work Unit допускается к route только тогда, когда в его Safe Operating Envelope помещаются: current goal/acceptance, применимые Intent/Hard Boundaries, contract текущей capability, one-hop dependencies, exact evidence, инструменты/instructions и достаточный reasoning/review margin. Nominal context maximum не является основанием отдать agent целую систему. Если decision-sufficient workset не помещается, задача декомпозируется, dependency view компилируется либо выбирается доказанно более подходящий route.

Architecture не превращает текущий effective context в постоянный лимит Module. Размер workset и Module является Empirical Profile: он может меняться с model, harness, tools, task family и качеством projections.

После correctness измеряются reconstruction cost, saved exploration, repeated context, latency, cost, human attention и missing-context regret. Noncritical injection желательно token-negative: она должна заменять более дорогую самостоятельную ориентацию, а не просто добавлять текст. Этот показатель не оправдывает потерю decision-relevant distinctions.

## A7.10. Skills

Skill должен быть коротким:

```text
trigger;
intent;
immediate action;
required writeback/output;
stop/escalation;
where-not-apply;
challenge path.
```

Deep semantics живут в Architecture, state, contracts и tools. Skill не заставляет agent администрировать Memory OS и не является enforcement boundary. Для Main Agent базовый instruction kernel сводится к пяти действиям: синхронизировать material state, сообщать существенные observation/decision/failure/outcome, действовать в видимой authority, проверять перед claim о завершении, challenge/escalate false block. Конфликтующие instructions/Skills становятся явным state и разрешаются по source, authority, scope и Intent, а не по порядку текста или последнему сообщению.

**ARCH-SKL-01 — Instructions are intent-dense and recovery-oriented.** Мало слов, одно значение, ясный следующий шаг, понятный выход из false block.

---
# A8. Watchdog

## A8.1. Назначение

Watchdog — отдельный daemon в независимом failure domain. Он работает непрерывно и независимо **в течение каждого заявленного активного интервала ELIOT**: пока существует observable Session/agent job, активная работа в зарегистрированном WorkScope, maintenance/recovery operation, внешний effect под supervision либо явно включённая пользователем supervision policy. Если ELIOT не используется и нет такой обязанности, Watchdog и остальные процессы могут остановиться после сохранения observation cursors, unresolved control state и future wake intent. Это не ослабление supervision: система заявляет coverage только для фактически наблюдаемого активного интервала и явно показывает blind gaps.

Он наблюдает, работает ли контур ELIOT так, как заявлено:

```text
живы ли Kernel, Governor, Doctor, hooks и integrations;
видит ли ELIOT действия агента;
поступают ли observations и outcomes;
не повторяется ли один failure без нового evidence;
не обходится ли canonical path;
не растут ли queue pressure, stale state и repair loops;
не появился ли security/injection/exfiltration signal;
не расходятся ли Architecture, Implementation и runtime.
```

Watchdog не решает project semantics, task goal, factual conflict, policy или completion.

**ARCH-WDG-01 — Independent supervision.** Хотя бы часть liveness, process, workspace и integration activity наблюдается вне self-report Governor и основного агента на всём интервале, для которого ELIOT заявляет independent supervision. Observable use активирует этот контур; вне активного интервала отсутствие запущенного Watchdog не изображается как наблюдение или coverage.

## A8.2. Гибридная структура

### Deterministic layer

Во время активного supervised interval непрерывно и дёшево проверяет:

```text
process/heartbeat;
hook cadence и sequence gaps;
workspace/filesystem activity;
protected process/path activity;
queue, storage и budget pressure;
module health и restart history;
version/config/plugin registration;
authority epochs и stale owners;
telemetry completeness.
```

### Watchdog Agents

Запускаются кратковременно для конкретного вопроса:

```text
объяснить anomaly;
проверить conformance;
проанализировать repeated failure;
провести security audit;
сформировать probe или repair alternatives;
подготовить concise brief агенту или человеку.
```

Они используют дешёвые модели по human-approved policy. Для high-impact uncertainty Watchdog может вызвать route другого vendor/family или Concilium, но не голосование.

## A8.3. Signal, Problem и Incident

```text
Signal — observed deviation;
Problem State — durable управляемая проблема;
Incident — тяжёлая проблема integrity, authority, security,
           critical telemetry или опасного unresolved effect.
```

Model assessment не открывает blocker/Incident самостоятельно. Это делает deterministic rule, policy или authorized Human decision.

Signal сохраняет evidence и может быть:

```text
informational;
warning;
blocking obligation;
incident candidate.
```

Processing, delivery и resolution независимы. Acknowledgement не закрывает проблему.

## A8.4. Контроль взаимодействия агента с ELIOT

Для Material task ожидается Interaction Heartbeat:

```text
session/task sync;
context boundary;
action intent;
material tool outcome;
failure;
verification;
finish attempt.
```

Если agent продолжает изменять workspace, но observations исчезают, Watchdog:

```text
фиксирует gap;
понижает supervision evidence;
требует resync;
ограничивает выдаваемую ELIOT authority и verified finish для зависимой high-impact работы; физически останавливает внешний effect только там, где это допускает фактическая Enforcement axis;
при устойчивой проблеме уведомляет Human.
```

Deterministic layer фиксирует observable divergence. Вывод о том, сохранён ли заявленный Intent, является fallible assessment Watchdog Agent/Main Agent/Human и не создаёт authority сам по себе. Отклонение от Skill или cadence является Signal, а не автоматическим нарушением, если task evidence и recovery остаются достаточными.

**ARCH-WDG-02 — Watchdog supervises preservation of declared intent, observable outcomes, security and recovery.** Его цель — обнаружить потерю управления и качества, а не заставить агента исполнять церемонию или стать semantic oracle.

## A8.5. Security supervision

Watchdog отслеживает:

```text
prompt/tool/memory injection;
authority laundering через summary или tool echo;
необычную массовую перезапись memory;
попытку прямой записи в storage;
remote query с exfiltration intent;
secret exposure;
poisoned source и resurrection after restore;
невидимую смену model/provider/tool definition.
```

Он оценивает source/effect risk, но не присваивает epistemic truth.

## A8.6. Recovery и escalation

При отказе Module или repeated failure Watchdog не повторяет одну команду бесконечно. Он меняет подход:

```text
другая diagnostic hypothesis;
другой tool или observation route;
другая model/vendor;
bounded adversarial audit;
alternate Module/route;
quarantine и Human escalation.
```

Критическая информация доставляется основному агенту и Human Control Plane как Diagnostic Brief: symptom, evidence, impact, attempted repairs, unknowns и next safe action.

---

# A9. Dreamer

## A9.1. Что такое Dreamer

Dreamer — отдельный supervised AI service/server. Он использует большую LLM, short-lived agents и при необходимости swarm там, где deterministic processing недостаточно.

Dreamer — не:

```text
Memory OS;
Governor;
canonical writer;
Researcher acquisition layer;
universal supervisor;
источник factual truth;
владелец Architecture, policy или completion;
автономный распорядитель денег.
```

Постоянной является сервисная роль и её contract, а не запущенный процесс или LLM-loop. Dreamer demand-start-ится для active query/job/maintenance obligation и может быть остановлен вместе с ELIOT вне active interval. Стандартный job loop:

```text
request/problem
→ bounded evidence bundle и State Fence
→ route/budget/privacy decision
→ one agent или swarm
→ structured candidate + lineage + uncertainty
→ form/provenance/loss checks
→ delivery Main Agent/Human/Governor
→ отдельный governed transition либо rejection.
```

Dreamer всегда возвращает candidate. Governor может автоматически принять по human-approved policy только механически проверяемое, обратимое изменение derived projection, organization или activation metadata, если оно сохраняет sources, epistemic support, dissent и meaning, не создаёт hard block и оставляет undo path. Semantic relation/merge, causal explanation, procedure, conflict resolution, изменение support/Current Epistemic Position, material forgetting, policy, authority, privacy и promotion требуют отдельного уполномоченного решения или verifier-backed transition.

**ARCH-DRM-01 — Dreamer is an instrumented intelligence service.** Он расширяет hypothesis space и организует знания, но возвращает candidates, а не authority.

## A9.2. Основные режимы

### Background curation

Dreamer анализирует Observation Candidates, episodes, relations, contradictions, duplicates, failures и procedures. Background jobs являются selective, batched, checkpointed и problem-driven; один observation не создаёт один LLM call. Он предлагает:

```text
classification и relation candidates;
episode reconstruction;
concept refinement;
duplicate/false-merge repair;
Failure Fingerprints;
procedure/Skill candidates;
reconsolidation и forgetting candidates;
Memory Repair Candidates.
```

### Interactive orientation

Main Agent или Human может спросить:

```text
что ELIOT знает по этой задаче;
какие решения, failures и alternatives связаны с областью;
какие contradictions и gaps существуют;
какие ARCH principles затронуты;
что мы, вероятно, пропускаем;
какой inquiry даст наибольшую пользу.
```

Dreamer возвращает problem-oriented packet, а не SQL/graph dump.

### Clarification

Dreamer может задать активному агенту короткий вопрос, если observation существенно, но непонятно:

```text
что именно наблюдалось;
каков scope;
это fact или interpretation;
какой outcome связан с decision;
когда опыт снова применим.
```

Человека беспокоят только вопросы, где требуется human-owned decision: goal/value, approval, privacy/security, необратимый effect, выход за cost envelope или high-impact ambiguity; а также случаи, когда Human явно запросил участие.

### Research synthesis

Dreamer может:

```text
формулировать research question;
строить rival hypotheses;
сравнивать sources;
искать contradictions и gaps;
запускать micro-audits и swarm;
синтезировать Research Brief;
предлагать discriminative experiments.
```

Он работает над governed sources и bounded source bundles. Acquisition, parsing, OCR, bulk logs/documents, indexing и RAG принадлежат будущему Researcher Module. До его появления raw corpora не записываются в Cognitive Inheritance напрямую: ELIOT сохраняет bounded observations, source/artifact handles и необходимые exact excerpts.

**ARCH-DRM-04 — Researcher acquires; Dreamer interprets; Governor governs.** Слияние acquisition, synthesis и canonical promotion в одном owner создаёт неконтролируемый data/influence path.

## A9.3. Dreamer и Concilium

Dreamer не сглаживает конфликт в один narrative. Его хороший результат содержит:

```text
strongest operational model;
rival models;
independent и shared evidence;
source dependence;
strong objections;
unknowns;
discriminative next steps;
conditions of invalidation.
```

**ARCH-DRM-02 — Dreamer expands and tests the hypothesis space.** Его ценность — не красивый summary, а обнаружение hidden relations, alternatives и полезного inquiry.

## A9.4. Запуск agents и swarm

Dreamer запускает agents только через Agent Coordinator и human-approved policy:

```text
allowed models/providers;
local/external routes;
data classes;
job families;
cost envelope;
fan-out/depth;
deadline и stop conditions;
independent review requirements.
```

Dreamer не запускает swarm «по собственному желанию». Если expected value не оправдывает стоимость, он предлагает query или небольшой job.

**ARCH-DRM-03 — Dreamer compute is human-governed.** Интеллектуальная глубина регулируется budget, privacy и explicit automation policy.

## A9.5. Interface и outputs

Теоретически обязательны три поверхности:

```text
Main Agent ↔ Dreamer;
Human ↔ Dreamer;
Watchdog/system jobs ↔ Dreamer.
```

Типовые запросы:

```text
Orientation Query;
Memory Query;
Architecture Query;
Research Query;
Curation Request;
Conflict Analysis;
Memory Repair Request.
```

Типовые результаты:

```text
Dream Packet;
Research Brief;
Architecture Brief;
Clarification Request;
Curation Candidate;
Conflict Brief.
```

Каждый результат содержит question, WorkScope/State Fence, evidence handles, model synthesis отдельно от evidence, rivals, unknowns, coverage gaps, route/cost и invalidation condition.

## A9.6. Remote Dreamer

Будущий online access допускается только как bounded question surface. Remote client не получает:

```text
database credentials;
raw canonical browsing;
local filesystem/tools;
write or agent-launch authority;
unfiltered operational telemetry.
```

Gateway аутентифицирует principal, ограничивает WorkScope/query class, фильтрует inputs/outputs, не исполняет embedded instructions и передаёт security signals Watchdog.

---

# A10. Harness, agents, Concilium и swarm

## A10.1. Agent interaction loop

Это логический control loop, а не синхронный checklist. Harness автоматически выполняет routine capture, state synchronization и admission; agent прерывается только у material uncertainty, conflict, missing authority/verifier или failure boundary.

```text
1. Attach session и WorkScope.
2. Восстановить task/commitments и Active View.
3. Выбрать inquiry или action.
4. Зафиксировать expected observable для Material causal decision.
5. Получить применимую authority.
6. Выполнить action через Harness.
7. Записать observations/effects.
8. Выполнить verifier или сохранить unknown.
9. Обновить task, memory и Theory Portfolio.
10. Завершить одним честным finish state.
```

На host с hooks этот loop реактивен. На tool-only host ELIOT использует доступные boundaries, obligations и finish discipline, не изображая полный control. Model, tool или swarm call оправдан, если ожидается новый evidence, изменение решения, artifact или proof; иначе он является лишней нагрузкой. Отклонённая write/action attempt не исчезает молча: ответ показывает причину, что сохранено, можно ли retry, какой repair/probe/authority нужен и какое действие разрешено следующим.

## A10.2. Impact и authority

Impact определяется effect, а не намерением агента:

```text
Observe — нет внешнего изменения;
Reversible — малый локальный откат;
Material — изменение поведения, нескольких ресурсов или внешнего state;
Critical — security, schema, credentials, irreversible/high-blast effect;
Forbidden — запрещено действующей Hard Boundary/Policy.
```

Main Agent предлагает класс. Governor выводит его из registered tool/effect profiles и affected resources. Неопределённость ведёт к probe или временному более осторожному классу, но не к бесконечному запрету.

**ARCH-ACT-01 — Effect defines impact and authority.** Риск определяется реальными affected resources, reversibility, observability и external consequences, а не уверенным rationale агента.

## A10.3. Action model

Для Material/Critical action должна существовать достаточная внешняя модель:

```text
intent и affected scope;
preconditions;
expected effect/observable;
invariants и known failures;
rollback/compensation;
verifier;
stop/revision condition.
```

Она может собираться автоматически из existing state. Архитектура не требует ритуального эссе от агента. Decision rationale, alternatives и revisit condition фиксируются у decision boundary; позднее объяснение хранится как retrospective hypothesis, а не как исходная причина.

Contract depth образует gradient:

```text
Primitive — observation, read, reversible probe;
Standard — Material action с scope, expected outcome и verifier;
Deep/Audit — Critical, novel или highly ambiguous work с rivals, independent challenge и recovery plan.
```

Глубина следует impact и uncertainty, а не привычке писать максимальный контракт для любой команды.

## A10.4. Делегирование

Каждый **Agent Work Unit** получает:

```text
одну основную causal property и одного primary owner;
точный question, expected artifact или evidence;
связь с current goal/acceptance;
frozen contract revision и применимые Architecture/Implementation handles;
минимально достаточный context: one-hop dependencies, known failures и exact anchors;
read/write/impact scope, allowed effects и explicit non-goals;
старое failing behavior, representation gap или missing capability;
discriminator/verifier и proof ceiling;
role, authority, State Fence, budget, checkpoint, cancellation и stop condition;
structured output и integration owner.
```

«Маленькая работа» определяется причинной замкнутостью, а не количеством файлов или строк. Если один дефект проходит через несколько owners, он раскладывается на contract/evidence unit, независимые Module units, edge/integration unit и Product Pulse; одному agent не выдаётся скрытый cross-system mandate.

Agent может вернуть Contract Challenge, если owner выбран неверно, discriminator измеряет proxy, contract противоречив или требуемый proof недостижим в выданном scope. Такой challenge не считается отказом от работы и направляется Task Controller/Concilium.

В одной active task ровно один Task Controller владеет current plan revision на Authority Epoch. Один mutable artifact scope имеет одного writer; read-only research/audit lanes могут быть параллельными. Workers не интегрируют собственные результаты автоматически: отдельный integration owner revalidates State Fence, affected edges и product outcome. Shared mutable plan не существует неявно.

Goals, instructions и constraints сохраняют source, authority, scope и status: active, superseded, expired или conflicting. Новая инструкция не накапливается поверх старой молча; unresolved conflict ограничивает только зависимые actions и создаёт interruption/reframing boundary.

## A10.5. Concilium и конфликты

Conflict локален. Он блокирует только transitions, которые зависят от unresolved issue.

Виды:

```text
factual;
scope/time;
semantic/causal;
state/write;
authority;
Watchdog ↔ Agent;
Architecture ↔ Implementation;
testimony/mental-state.
```

Conflict Directive показывает observations, candidates, common lineage, unresolved residue, полезный probe, decision owner и временно допустимые actions.

Evidence и practical tests важнее consensus. Provisional decision допустим под explicit risk; dissent сохраняется с revision trigger.

## A10.6. Agent swarm и конвейерная работа

Swarm используется, когда decomposition и ожидаемая дополнительная coverage оправдывают orchestration cost. Main Agent или Dreamer запрашивает его только через Agent Coordinator и применимую human policy. Model может предложить plan, но durable execution graph появляется только после проверки dependencies, ownership, effects, budgets, privacy, stop conditions и proof paths. Свободный group chat не является control plane.

ELIOT поддерживает как минимум два совместимых конвейера.

Исследовательский:

```text
Map/Audit
→ independent Challenge/Falsification
→ Reduce/Synthesis
→ decision or new inquiry
→ Verify.
```

Инженерный:

```text
Contract/Evidence
→ parallel Module/Capability work
→ affected Edge/Integration proof
→ Product Pulse
→ promotion, rollback or Mechanism Review.
```

Main Agent может запускать сотни узких exact audits, затем отдельные challenge/synthesis/implementation branches; масштаб не отменяет bounded scope каждого Agent Work Unit. Первичный independent audit по возможности не получает sibling conclusions до собственной submission; disclosure поздних findings явно меняет Independence Profile.

Swarm Plan задаёт objective, immutable work graph revision, budgets, privacy, routes, independence profile, WIP limits, stop conditions и aggregation/integration owners. Каждый worker получает minimum decision-sufficient packet:

```text
shared immutable root: goal, relevant Architecture, current epistemic position;
role и exact work unit;
one-hop contracts/relations и load-bearing evidence;
allowed tools/effects, non-goals, verifier и stop condition;
just-in-time fired memory.
```

Whole-project dump и полные transcripts других agents не являются default. Structured result возвращает artifacts, evidence, uncertainty, unresolved questions, proposed effects и Evidence Lineage; prose может быть artifact, но не заменяет эти поля.

Confidence зависит от:

```text
unique coverage;
Evidence Lineage;
independent observation/evaluation routes;
разных failure domains;
разных conceptual frames;
сильных negative findings.
```

Сто agents на одном packet не создают сто подтверждений. Synthesis сохраняет dissent, minority findings и gaps; он не получает authority интегрировать artifact или объявлять truth.

Partial verified results не теряются из-за падения одной ветви. Replanning заменяет только affected branches. История swarm сохраняется как trace, но epistemic support любой ветви остаётся defeasible и может быть отозван при stale scope, invalid verifier, poisoned shared root или зависимой Evidence Lineage.

**ARCH-SWM-01 — Swarm is a bounded, context-minimal evidence pipeline.** Каждый attempt выполняет определённую работу в проверяемом stage; swarm расширяет coverage и capability, но не становится collective truth, shared-chat control plane или value authority.

## A10.7. Long-running work

Работа на часы и недели живёт в durable state:

```text
tasks и commitments;
work graph;
Durable Jobs;
checkpoints;
State Fences и Authority Epochs;
Decision, Unknown, Failure и Artifact ledgers;
Coordination Events;
budgets и progress trends.
```

Assignments, claims, heartbeats, checkpoints, cancellations и results существуют как durable idempotent Coordination Events, связанные с work item, causal predecessor, State Fence и Authority Epoch. Retry использует ту же identity; reassignment сначала fence-ит прежнего owner.

Потеря agent context, coordinator или process не уничтожает подтверждённую работу. На reconciliation boundaries система пересматривает State Fences, open Problems/Conflicts, stalled branches, budgets, invalidated evidence и следующий safe action; Watchdog инициирует review по drift, а не только по timeout.

**ARCH-SWM-02 — Swarm coordination survives agents and retries.** Координация durable, idempotent и epoch-fenced; process не является единственным носителем assignment или результата.

**ARCH-LONG-01 — Long work lives in durable state.** Session и model route являются сменяемыми исполнителями, а не единственным носителем plan, evidence и commitments.

## A10.8. Verification и finish

Finish states:

```text
VERIFIED_COMPLETE;
PARTIAL;
BLOCKED;
FAILED_VERIFICATION;
DEGRADED_NO_PROOF;
UNSAFE_TO_FINISH;
CANCELLED;
SUPERSEDED.
```

Только `VERIFIED_COMPLETE` называется выполненной задачей. Остальные состояния честно сохраняют artifacts, effects, gaps и continuation.

Professional work подтверждается artifact, допустимым method/environment и соответствующим evaluator, а не правдоподобным текстом. Artifact может быть code, document, spreadsheet, report, image/video, GUI state, service или research result; proof соответствует его modality и required shape.

**ARCH-FIN-01 — Completion is proof-bearing.** ELIOT помогает продвигаться при неполноте, но не превращает partial progress в done.

---

# A11. Human control и настройка системы

## A11.1. Human authority и fallibility

Human задаёт values, goals, acceptable risk и legitimacy, но может:

```text
не знать фактов;
менять мнение;
иметь конфликтующие роли;
не читать evidence;
поддаваться automation bias;
терять situational awareness.
```

Поэтому ELIOT не только сохраняет human authority, но и помогает clarify preferences, сравнить alternatives и восстановить state без активной модели.

## A11.2. Первичная установка

Trust root создаётся deterministic human interaction. Installation Survey обнаруживает возможные agents, harnesses, tools, IDE, model routes, adapters и verifiers безопасными metadata/version probes.

Непроверенный executable не получает secrets или elevated authority.

Setup спрашивает только решения, которые реально меняют privacy, cost, authority или доступ к внешним системам. Остальное получает понятные, обратимые и видимые defaults; advanced configuration остаётся optional.

Пользователь выбирает:

```text
какие integrations включить;
какие models/routes использовать для Main Agent, Workers, Auditors, Watchdog, Dreamer и evaluation;
local/external data boundaries;
job/task/period budgets;
какие Dreamer/Watchdog jobs можно запускать автоматически;
swarm fan-out/depth;
кто может approve Critical actions;
разрешён ли remote Dreamer.
```

Setup Agent может объяснить варианты после создания trust root, но не создаёт authority и не записывает configuration без human confirmation.

## A11.3. Capability Registry

Registry хранит наблюдаемую способность:

```text
installation identity и version;
transport, lifecycle, hooks и tool coverage;
model route, cost, privacy и availability;
competence/context profiles;
verifier validity/freshness;
failure-domain and evidence independence profile;
known biases и failure signatures;
health и allowed WorkScopes/principals.
```

Profile dependencies включают model/provider version, inference regime, harness, Tool Definitions, context policy, evaluator и relevant data distribution. Их изменение делает dependent profiles provisional до requalification.

## A11.4. ControlBoardView

Одна canonical role-filtered projection используется Main Agent, Watchdog, Dreamer, Human UI и read-only API.

Она показывает:

```text
active tasks, plans, swarms и checkpoints;
Current Epistemic Position, rivals и unknowns;
conflicts и Critical Attention;
verification и finish readiness;
Governance Profile;
modules, models, tools, storage и integration health;
Problem/Incident, repair и recovery state;
memory health и blind areas;
cost/privacy state;
Improvement Candidates;
active goals, commitments и safe next action.
```

Human может inspect evidence, acknowledge/resolve attention, approve, pause/cancel/replan task или swarm, challenge rule, запустить Dreamer/Watchdog query и выполнить recovery action.

## A11.5. Notifications

Notifications имеют severity, owner, evidence, dedup, cooldown, acknowledgement и resolution state. Все unresolved Action-required/Critical items остаются в persistent inbox независимо от transient toast/channel.

```text
Critical — integrity, security, unknown external effect, unrecoverable control loss;
Action required — approval, blocked task, credential/integration failure;
Warning — repeated agent failure, hook loss, queue pressure, stale backup/profile;
Info — verified completion, onboarding, audit/research report.
```

Доставка не равна решению. Alert fatigue и пропущенные уведомления измеряются.

**ARCH-HUM-01 — Human remains in control without constant micromanagement.** ELIOT автоматизирует ceremony, но сохраняет понятную картину, decision points и возможность вмешаться на любом этапе.

---
# A12. Security, provenance и bounded influence

## A12.1. Security assumes breach

ELIOT не предполагает, что prompt injection, poisoned memory, malicious tool definition или compromised model всегда будут обнаружены заранее.

Защита строится слоями:

```text
Hard Boundaries;
buffering;
разделение instruction/data/evidence/authority;
origin-bound provenance;
ограничение allowed influence и effects;
multiple independent routes;
quarantine и revocation;
backup/restore и recovery;
Watchdog observation;
Human escalation.
```

**ARCH-SEC-01 — Assume compromise; preserve control and recovery.** Security считается успешной, если breach не получает скрытую authority, ограничен по blast radius, обнаружим и обратим.

## A12.2. Principal, Session и visibility

Identity не является self-declared строкой модели. Harness/installation boundary устанавливает principal и связывает его с Session, WorkScope, capabilities, visibility и Authority Epoch.

Session lifecycle conceptually:

```text
attach → active → suspended → detached | expired | revoked.
```

Каждый read, Active View, model bundle, notification и write фильтруется по principal, WorkScope, visibility и policy. Unknown identity означает minimum privilege и отсутствие Material authority.

## A12.3. Один governed write path

Agent, Dreamer, Watchdog Agent, Doctor и external service не получают прямой canonical write path.

```text
proposal/observation
→ admission и provenance
→ governed transition
→ canonical receipt.
```

Логически единый semantic transition атомарно связывает event/history, current projections, affected revisions и receipt. Если substrate не даёт общей атомарности для нескольких scopes или external effects, используется explicit staged/saga transition с видимыми partial outcomes.

Direct storage access, shell/DB-protocol обход или второй writer являются security/integrity problem независимо от правдоподобия content.

**ARCH-SEC-02 — One canonical transition path.** Recovery interface может сохранять intent и evidence, но не становится скрытым вторым Governor.

## A12.4. Source Assurance и injection

Source оценивается по независимым axes:

```text
identity и provenance;
integrity и freshness;
domain competence;
incentives и track record;
evidence independence;
privacy/sensitivity;
instruction-injection risk;
deception/exfiltration/persistence risk;
allowed epistemic use;
allowed effects;
required verifier;
quarantine/review.
```

Instruction Taint отвечает на вопрос, может ли content командовать системой. Origin Assurance отвечает, откуда observation. Semantic Screening отвечает, проверено ли содержание на contradiction, overgeneralization и hidden instruction. Эти свойства не смешиваются.

Embedded text никогда не становится instruction по содержанию. Authenticated Human создаёт новую direct instruction record в своей authority, а не «очищает» исходный документ. Подозрительный material не обязан удаляться: он изолируется, сохраняет provenance и может быть передан Dreamer для semantic analysis и Watchdog для security analysis в bounded bundle без повышения influence.

## A12.5. Origin-bound influence

Summary, tool echo, agent restatement, Dreamer merge, compaction и повтор разными agents сохраняют authority ceiling источника.

Если source, Tool Definition, verifier или derived item признаны poisoned, revoked, wrong-scope или invalid, применяется **Influence Dependency Closure**:

```text
history и forensic lineage сохраняются;
current support и allowed influence снимаются;
dependent packets, indexes, procedures, swarm findings и confidence claims инвалидируются;
restore/reindex не возвращает influence;
независимое evidence может локально восстановить support.
```

Revocation распространяется по explicit dependency closure, а не similarity. Неполная lineage создаёт scoped quarantine/unknown, а не глобальное удаление памяти.

**ARCH-SEC-03 — Influence remains tied to origin and is revocable.** Transformation не отмывает provenance и authority.

## A12.6. External model routes и secrets

Model job содержит question, bounded inputs, State Fence, privacy class, route class, budget, deadline, allowed effects, cancellation и receipt.

Secret/credential lifecycle:

```text
минимальная scope visibility;
не передавать model, logs или memory без явной необходимости;
rotation/revocation при compromise;
no command-line/plaintext leakage;
backup/restore с тем же privacy level;
human confirmation для расширения внешней передачи.
```

Provider fallback не расширяет data access и cost молча. Provider-native memory рассматривается как external source/feed с собственными retention и deletion semantics; она не становится canonical owner, policy или current support без normal ELIOT reconciliation.

**ARCH-SEC-04 — Model output remains a candidate until a governed transition accepts its effect.** Ни model role, ни число согласных routes, ни уверенный format не создают authority, factual support или completion.

Remote Dreamer является отдельным external principal и read-oriented semantic surface. Он не получает local tools, database handles, writes или agent-launch authority.

## A12.7. Skills, guards и challenge

Skills и prompts помогают, но не являются security boundary.

Защита от ошибающегося агента:

```text
убрать лишнюю ceremony;
автоматически capture очевидные observations;
проверять Hard Boundaries инструментально;
наблюдать bypass и telemetry gaps;
давать Recovery/Conflict Directive;
предоставлять legal challenge path.
```

Governed Challenge содержит rule, false block, evidence, более узкую boundary/probe, owner и review horizon. Независимая работа продолжается. Если Hard Boundary не затронута, допускается Recoverable Deviation.

## A12.8. Privacy erasure

Privacy erasure — отдельный governed process. Он распространяется на canonical payload, projections, indexes, Operational Recovery State, Route Continuation State, provider-side copies, backups и restore path в пределах технической/правовой возможности.

Purge ledger сохраняет non-revealing факт и scope удаления, не восстанавливая content. Restore применяет purge ledger до cutover.

**ARCH-PRIV-01 — Erasure removes future availability without rewriting unrelated history.** Нельзя подменять deletion suppression или resurrect удалённое из backup.

---

# A13. Resilience, recovery и observability

## A13.1. Let it fail locally

ELIOT следует принципу **let it crash**, но не трактует его как безразличие к данным.

```text
process или agent может умереть;
operation может завершиться частично;
Module может быть quarantined;
model result может оказаться неверным;
queue может отвергнуть work;
```

При этом должны пережить failure:

```text
canonical history;
confirmed artifacts/evidence;
ownership и State Fences;
independent work;
Problem State;
recovery entrypoint;
возможность продолжить или честно остановиться.
```

Resilience имеет три разные цели: operational сохраняет процессы/state/effects, epistemic не превращает потерю данных в ложную уверенность, cognitive сохраняет goals, alternatives, commitments и способность продолжить inquiry.

**ARCH-RES-01 — Fail locally, recover globally.** Optional failure уменьшает capability, а не уничтожает весь ELIOT.

## A13.2. Kernel и failure domains

Минимально живой Kernel способен:

```text
не выдать недоказанную authority;
сохранить или безопасно заморозить canonical state;
показать health и unavailable guarantees;
принять cancellation/recovery request;
fence stale owners;
управлять lifecycle независимых Modules.
```

Kernel не зависит от model call, Dreamer, graph, external provider, UI или одного adapter.

Host Supervisor находится вне общего process failure domain Kernel, Watchdog и Doctor. Он запускает, останавливает и bounded-restarts approved services, но не читает project semantics и не принимает repair hypothesis. Kernel, Watchdog и Doctor имеют отдельные service identities и restart budgets; повторный отказ любого из них становится Problem State вместо бесконечного restart loop.

Последняя честная граница: если потеряны Host Supervisor, ОС/машина и fallback notification path, ELIOT не обещает сообщить о собственном полном исчезновении. Это platform/manual recovery.

## A13.3. Module supervision и Doctor

Module lifecycle должен позволять:

```text
start;
health/readiness check;
quiesce/drain;
checkpoint;
restart/rebuild;
replace/rollback;
quarantine;
retire.
```

Replacement:

```text
stop new work
→ checkpoint/drain
→ fence old Authority Epoch
→ replace
→ health/evaluation
→ resume or rollback.
```

Для экспериментальной capability normal promotion path:

```text
contract/conformance
→ recorded replay
→ effect-free shadow
→ bounded canary
→ active generation
→ drain/retire или forward rollback.
```

Shadow не выполняет внешний effect, не изменяет canonical state, scheduling, policy или memory influence; он создаёт divergence evidence. Promotion в более тесно интегрированный или hot-path contour требует не только correctness, но и измеримого выигрыша, совместимого failure envelope и доказанного rollback. Last-known-good означает совместимость с durable formats, policy и recovery state, а не просто прошлый успешный запуск.

Doctor работает от Module Registry, Problem State, Diagnostic Brief и registered repair recipes. Сам Doctor является обычным supervised Module: Host Supervisor может вернуть last-known-good build, а повторный отказ эскалируется без попытки Doctor «лечить себя».

Repairs:

```text
automatic-safe — idempotent restart/reconnect, cache/index rebuild, stale-session cleanup;
guarded — config, credentials, integration, schema/data repair и cutover через approved recovery intent и canonical transition;
diagnose-only — corruption, unknown ownership, unclear external effect, repeated failure.
```

Doctor не пишет canonical state напрямую: он формирует repair intent, выполняет только разрешённый infrastructure effect и возвращает evidence; применимый semantic transition выполняет Governor/Kernel recovery boundary.

Repair имеет attempt budget, cooldown, verification и receipt. После исчерпания budget automation прекращается, Module quarantined, problem escalated.

**ARCH-RES-02 — Self-repair is bounded and verified.** Doctor не угадывает бесконечно и не становится вторым writer.

## A13.4. Problem lifecycle

```text
OPEN
→ TRIAGED
→ DIAGNOSING | CONTAINED | REPAIRING
→ VERIFYING
→ RESOLVED | ACCEPTED_RISK | SUPERSEDED | QUARANTINED.
```

New evidence может reopen problem. Owner имеет review/lease condition; потеря owner не закрывает problem, а вызывает reassignment/escalation.

Signal, restart, notification и acknowledgement не являются resolution.

Если Governor недоступен, Kernel/Watchdog сохраняют только `problem/incident intent` и evidence locator в Operational Recovery State; canonical Problem State создаётся после reconciliation.

## A13.5. Bounded resources и Control Reserve

Queues, buffers, jobs, model calls, agents и outage spool ограничены.

При saturation:

```text
новый work получает backpressure;
accepted operation сохраняет identity;
background уступает interactive/verification;
noncritical enrichment сбрасывается первым;
одна poison operation уходит в dead-letter/quarantine;
independent Ordering Scopes продолжаются;
false acceptance запрещён.
```

Admission и scheduling изолируют budgets по Module, principal, task и swarm: одна ветвь не может вытеснить независимую работу или Control Reserve.

Control Reserve защищает capacity для:

```text
cancellation и fencing;
health и critical telemetry;
Critical Attention/Problem/Incident transitions;
persistent notification inbox;
safe shutdown;
recovery.
```

Reserve существует в каждом relevant bottleneck, а не только как высокий priority. Его потеря фиксируется через last-resort path вне normal workload. Если и он недоступен, система явно теряет control guarantee.

## A13.6. Operational Recovery State

При недоступном каноне сохраняются только:

```text
operation identity и opaque envelope/artifact locator;
idempotency, sequence и reconciliation state;
job checkpoint/cancellation;
Authority Epoch и suspended leases;
module health/restart attempts;
problem/incident intents;
Recovery Manifest, backup pointers и integrity anchors.
```

ORS не интерпретирует content как claims, decisions, Current Epistemic Position или project graph и не выдаёт authority. Privacy и provenance сохраняются. После возврата канона operations reconciled по receipt до replay. Неизвестный commit/external-effect outcome сначала разрешается по operation identity и observations; blind retry запрещён.

## A13.7. Backups, restore и migration

Backup включает canonical state, referenced immutable artifacts, policy/config snapshots, required pending operational state, purge ledger, Architecture revision digest, manifest и checksums.

Restore выполняется в изолированную область и проверяет:

```text
schema/format compatibility;
provenance и integrity;
privacy purge/revocation closure;
semantic inheritance preservation;
Authority Epoch monotonicity;
external-effect reconciliation.
```

Cutover требует отдельной authority. Старые sessions, leases, approvals и epochs не оживают. Новая Authority Epoch lineage должна быть строго новее всех наблюдавшихся значений либо globally distinct, если общий максимум доказать невозможно.

Canonical migration — governed transformation, а не обычный restart:

```text
backup и isolated rehearsal;
coverage/preservation/faithfulness proof;
compatibility window;
checkpoint/resume;
explicit irreversible boundary;
Human authority;
rollback или recovery plan.
```

**ARCH-RES-03 — Recovery cannot resurrect invalid state.** Backup, restore, reindex и migration сохраняют history, purge, revocation и fencing.

## A13.8. Integrity

Периодический integrity review проверяет:

```text
canonical references и receipts;
ordering и epoch consistency;
provenance/dependency closure;
revocation и purge propagation;
Architecture digest и conformance map;
backup recoverability;
projection rebuildability.
```

Он создаёт Problem State и repair plan; не исправляет semantic conflict молча.

External integrity anchors хранят digest/identity, а не копию semantic memory, и помогают обнаружить rollback/history rewrite.

## A13.9. Concurrency и durable execution

Правило:

```text
parallel where independent;
ordered where causal.
```

Одна canonical write authority не означает один глобальный writer thread: независимые Ordering Scopes выполняются конкурентно через bounded lanes/tasks, а причинно конфликтующие transitions упорядочиваются.

Conflicting transitions одного Ordering Scope имеют одного owner. Multi-scope operation заранее объявляет Coordination Scope и использует deterministic ordering либо explicit saga с видимыми partial outcomes.

Нельзя удерживать transaction, exclusive owner или global lock во время unbounded ожидания model/tool/network. Сначала фиксируются intent и State Fence, затем external work, затем idempotent fenced reconciliation.

Durable Job имеет identity, owner, checkpoint, budget, cancellation, State Fence и outcome. At-least-once execution допустим только при idempotent/fenced/reconciled effects.

Job completion не равен Task completion:

```text
COMPLETED job → candidate artifact/result;
PARTIAL/FAILED/CANCELLED/STALE job → coverage gap или replanning;
Task VERIFIED_COMPLETE → только через acceptance verification.
```

**ARCH-ORD-01 — Parallel where independent; ordered where causal.** Concurrency увеличивает throughput, но не отменяет единственного owner конфликтующего state, fencing и reconciliation.

## A13.10. Observability и Diagnostic Brief

Разделяются:

```text
Operational logs — диагностика, могут ротироваться;
Metrics — агрегаты/trends;
Durable audit — authority, transitions, receipts и incidents;
Reports — human/agent projections.
```

Красивый report не доказывает transition; отсутствие log line не отменяет receipt. Operational logs не становятся Cognitive Inheritance автоматически: в память переходят только anchored observations и diagnostic evidence, а bulk external logs/documents требуют Researcher acquisition path. Потеря lifecycle, authority, material action, verification, Incident или Critical Attention telemetry сама становится Problem State, понижает доказуемые guarantees и не закрывается ретроспективным рассказом модели.

Agent не обязан искать неизвестную проблему в raw logs. Для crash, timeout, deadlock, failed verification, unknown outcome или regression ELIOT сохраняет воспроизводимый Failure Capsule: exact Product/Task/Attempt identity, State Fence, inputs/artifact generations, event tail, tool/process identities, effect disposition, raw evidence handles, применимый seed/schedule/failpoint, минимальный rerun и current hypotheses.

Из него ELIOT компилирует Diagnostic Brief:

```text
symptom и severity;
affected Module/WorkScope/tasks;
causal timeline и evidence handles;
correlated changes и graph relations;
prior failures и attempted repairs;
unknowns;
next discriminator, probe, repair или escalation.
```

Correlation остаётся hypothesis до intervention/evaluation evidence. Повторная отладка должна начинаться с воспроизводимого discriminator, а не с нового широкого чтения logs.

**ARCH-OBS-01 — Logs, metrics, audit and reports are distinct.** Диагностический поток помогает понять проблему, но authority и факт transition подтверждаются receipts/evidence.

## A13.11. Degradation by subtraction

| Отказ | Что сохраняется |
|---|---|
| Model/Dreamer unavailable | Deterministic memory, state, tools и partial work |
| Adapter/truth surface unavailable | Other surface, probe или explicit unknown |
| Verifier unavailable | Work may continue; verified finish недоступен |
| Watchdog unavailable | Supervision profile понижается; ELIOT authority/verified finish ограничиваются policy в пределах фактической Enforcement axis |
| Host Supervisor unavailable | Уже работающие services могут продолжить; automatic process recovery недоступен, Watchdog открывает Problem State |
| Kernel unavailable, Host Supervisor alive | Normal authority/effects stop; approved restart/rollback и fallback notification выполняются вне semantic path |
| Doctor unavailable | Normal work continues; automatic repair unavailable |
| Optional Module failed | Local capability degrades; Kernel and independent work live |
| Governor app unavailable, Kernel alive | Fencing, cancellation, ORS и Recovery View; no new semantic/material authority |
| Canonical store unavailable | Bounded operational staging only; no semantic promotion/verified finish |
| Operational Recovery State unavailable | No durable pending-acceptance, outage checkpoint or automated replay claim; new affected work is rejected with visible recovery boundary |
| Agent/Coordinator unavailable | Durable work/checkpoints survive; ownership reassigned |
| Human unavailable | Safe delegated work may continue; approvals/value decisions wait |
| Budget exhausted | Paid jobs stop; verified partial work and coverage gap remain |

**ARCH-RES-04 — Degradation is visible and local.** Система уменьшает обещания раньше, чем выдаёт неполное состояние за полное.

## A13.12. Recovery as learning

Каждый существенный failure сохраняет:

```text
symptom и scope;
competing hypotheses;
repairs/routes tried;
observed delta;
useful model/tool/vendor;
unresolved cause;
change candidate для Skill, Module, procedure или Architecture.
```

Повторный сбой должен менять hypothesis или method, а не только увеличивать retry count.

**ARCH-RES-05 — Recovery produces reusable knowledge.** Лечение улучшает следующую диагностику, но один успешный repair не становится универсальной procedure без transfer evidence.

---
# A14. Learning, Meta и развитие системы

## A14.1. Уровни learning

ELIOT различает:

| Уровень | Что меняется |
|---|---|
| Memory update | Episode, observation, commitment или outcome |
| Epistemic learning | Support, scope, rivals и Current Epistemic Position |
| Procedural learning | Procedure, Skill, route и recovery behavior |
| Conceptual learning | Categories, ontology boundaries и analogies |
| Strategic/metacognitive learning | Inquiry, decomposition, context и evaluator strategy |
| Institutional learning | Policy, Module contracts, governance и Architecture |
| Parametric learning | Model weights во внешнем training process |

ELIOT главным образом изменяет external inheritance. Training weights может дополнять, но не заменяет этот loop.

**ARCH-LEARN-01 — Learning changes external inheritance through grounded outcomes.** Будущее поведение меняется только через evidence-linked revision, procedure, routing, policy candidate или иной inspectable state.

## A14.2. Consolidation и reconsolidation

```text
Primary consolidation:
new episode → candidate concept/model/procedure
→ validation и transfer test.

Reconsolidation:
reactivated derived knowledge + new outcome/evidence
→ revise meaning, scope, support или activation.
```

Raw episode не переписывается. New single outcome сначала меняет local scope/support; broad promotion требует repeated или independent evidence.

Stability–plasticity защищает от двух крайностей:

```text
новый случай не превращается сразу в doctrine;
старое high-use knowledge не блокирует contradictory evidence.
```

## A14.3. Negative memory и extinction

Failure memory содержит trigger, failed action, outcome, violated invariant, scope, reopen и extinction conditions.

Exact deterministic trigger может блокировать. Semantic similarity создаёт warning или inquiry obligation, но не hard block автоматически.

После изменения среды safe re-exposure может подтвердить, сузить или extinguish прежний avoidance response. Исходный failure episode сохраняется.

## A14.4. Forgetting и memory ecology

Forgetting operators:

```text
suppress/demote accessibility;
compress с loss/lineage record;
archive/quarantine;
extinguish obsolete activation;
post-supersession demotion;
privacy purge по отдельному contract.
```

Low use не уменьшает factual support. Frequent retrieval не усиливает record. Minority evidence не удаляется popularity.

Memory health оценивает:

```text
stale reuse;
false promotion;
wrong-scope reuse;
negative transfer;
poisoned influence;
cue overload;
false activation/block;
missing-context regret;
compaction loss;
capture/curation/restore cost;
failures prevented и decisions improved.
```

Influence различает stages `present → attended → interpreted → used → causally helpful`. Delivery, citation и confident rationale не доказывают contribution без downstream outcome или counterfactual evidence.

**Memory gravity** отмечает records или narratives, которые доминируют context непропорционально evidence и utility. Она ведёт к narrowing/suppression candidate, но не к автоматическому удалению minority evidence.

## A14.5. Meta-learning

Meta loop:

```text
problem, repeated failure, false block, Recoverable Deviation, memory contamination, Architecture/Implementation conformance gap или performance drift
→ competing root-cause hypotheses
→ Concilium, replay, audit или swarm
→ Improvement Candidate
→ bounded canary/experiment
→ observed delta и counter-metrics
→ keep, narrow, rollback, reject или escalate.
```

Improvement Candidate содержит evidence, validity scope, owner, expected delta, risk, rollout, rollback и stop condition. Advice может быть immediate (next inquiry/action), task-level (procedure/failure), system-level (routing/module/memory) или architecture-level (решение Architecture Owner).

По умолчанию Meta советует Main Agent или Human. Реальная работа над проектами является источником evidence для улучшения decomposition, Module boundaries, context, Skills, routes, tests, repair recipes и promotion policy. Она не даёт production generation права переписывать себя.

Изменение готовится как отдельный candidate в isolated Experimental Contour/branch, проверяется на fixed replay и affected proofs, затем при необходимости проходит shadow/canary и reversible cutover. Активная generation остаётся immutable до governed promotion. Автоматически применяются только заранее разрешённые, локальные, обратимые tuning changes с canary и rollback.

Качество самого Meta-контура оценивается по verified delta, adoption, regressions, false positives, noise, cost и влиянию на Product Pulse; бесполезные советы demoted или archived. Code, schema, authority, verifier definitions, privacy, Architecture и destructive forgetting не меняются автоматически.

**ARCH-META-01 — Self-improvement is advisory, isolated and falsifiable.** ELIOT улучшает себя по evidence реальной работы через candidate, replay, shadow/canary и rollback, а не через самоуверенный rewrite активной системы.

## A14.6. Evaluation

Различаются:

```text
Production path — что создало decisions/actions/outcome;
Measurement path — как outcome превратился в score/quality claim;
Optimization-feedback path — как evaluation изменяет будущую систему.
```

Evaluator проверяется по construct, criterion, ecological, consequential, temporal и comparative validity. Same-family model judge не считается независимым автоматически. Performance claim относится ко всей связке model, harness, memory/context state, tools, evaluator, environment, policy, budget и Human involvement, а не к одному имени модели.

Decision quality не сводится к lucky outcome; оцениваются доступное evidence, alternatives, reasoning discipline, risk и calibration.

## A14.7. Cost authority

System Owner задаёт доступные routes, общие privacy/cost ceilings и automation policy. Requester задаёт task budget и preferences внутри этих границ; Task Controller может только сузить. Governor/Agent Coordinator учитывает фактическое consumption по provider/tool receipts и attribution к task/job/swarm.

При exhaustion:

```text
новые paid jobs не запускаются;
active work checkpointed;
verified partial work сохраняется;
coverage gap и options видимы;
unauthorized expensive fallback запрещён.
```

**ARCH-ECON-01 — Cost is authority.** Intelligence имеет цену; system service не создаёт bill без owner и envelope.

## A14.8. Development doctrine

ELIOT проектируется с учётом того, что разработку выполняют fallible agents, склонные оптимизировать ближайший test, expression или status. Поэтому task decomposition, testing и integration обязаны сохранять causal link от user goal/acceptance до observable outcome.

Нормальный цикл развития:

```text
1. Построить minimum vertical spine A0.8 и использовать его в реальной работе.
2. Выбрать одну causal property и фактический production owner/path.
3. Зафиксировать old failing behavior или missing capability и discriminator.
4. Разложить работу на Contract/Evidence, Module, Edge/Integration units.
5. Выполнить bounded parallel work над независимыми Modules.
6. Получить Module proof, затем affected Edge proof.
7. Выполнить smallest Product Pulse, способный обнаружить architectural drift.
8. Promote, narrow, rollback или открыть Mechanism Review.
9. Записать outcome в memory, tests, Skills, repair/decomposition candidates.
10. Удалять ceremony и mechanisms без decision delta.
```

Каждый поддерживаемый Module имеет independently invokable proof surface. Это не означает, что Module обязан иметь фиксированный размер, отдельный process или полностью независимую compilation universe. Самостоятельность означает ясный contract, bounded fixtures/environment, воспроизводимый entrypoint, точную failure attribution и известный proof ceiling.

Proof levels не смешиваются:

```text
Module Proof — capability за собственным contract;
Edge Proof — реальное взаимодействие provider/consumer или runtime boundary;
Product Proof — end-to-end user/agent outcome;
Release Proof — принятая Product Identity, recovery и distribution boundary.
```

Локальный PASS не повышается автоматически. Product Pulse специально проверяет, не превратилось ли множество local greens в общий failure.

Testing и debugging выполняются непрерывно и пропорционально change closure:

```text
изменённый Module и его contract;
affected dependency/consumer edges;
выбранные recovery/security/concurrency paths;
полная release matrix только при соответствующем blast radius или release.
```

Первый test repair начинается с discriminator, который падает на exact old path. Ноль выполненных ожидаемых tests не является PASS. Agent, изменяющий implementation, не ослабляет oracle, fixture truth, tolerance или verifier semantics в той же work unit без отдельного decision/review. Для concurrency, retries, cutovers и recovery применяются deterministic simulation/fault injection там, где они различают interleavings; simulation не заменяет хотя бы один real-edge/live proof.

Testing в процессе работы не означает изменение active generation на месте. Candidate Module проверяется в isolated environment, replay/shadow/canary; background tests не вытесняют active work, Control Reserve или Human attention. Failure создаёт Failure Capsule и следующий discriminator, а не только ещё один широкий suite.

Тест ценен, если он:

```text
различает competing implementation hypotheses;
защищает уже наблюдаемую ценность;
проверяет effect, integration, recovery или migration;
предотвращает повтор реальной ошибки;
ловит proxy success до того, как он станет product regression.
```

Количество Modules, tests, phases, reports и certificates не является прогрессом без Product Proof. Topology и test strategy сами являются Improvement Candidates и меняются по agent success, context usability, build/test cost, escaped failures и Product Pulse.

**ARCH-DEV-02 — Depth grows through independently testable layers under stable intent.** ELIOT не переписывается целиком при каждой новой модели или runtime technique; Modules, proofs и promotion contours развиваются по наблюдаемой ценности и failure evidence.

## A14.9. Architecture coherence review

Перед принятием Architecture/Implementation проверяются:

```text
сохранена ли главная задача понимания;
не превратились ли Intent в буквоедство;
нет ли второго owner или hidden authority;
не смешаны ли evidence, model output и proof;
локализуются ли failures;
есть ли recovery and learning loop;
не стала ли Implementation заложником текущего vendor;
не подменена ли работа тестами и отчётами;
размер Modules/work units обоснован empirical outcome, а не превращён в вечный threshold;
получает ли каждый swarm worker minimum decision-sufficient context вместо whole-project dump;
замыкаются ли local Module proofs на affected edges и Product Pulse;
может ли человек понять состояние и вмешаться;
может ли новый агент кратко объяснить mission, применимые Intent/Hard Boundaries, current goal и next proof без чтения всей истории.
```

Audit является fault list и evidence, но не третьей нормативной книгой. Watchdog, Dreamer и внешние auditors могут формировать findings; изменение принимает Architecture Owner в основном тексте.

---

# A15. Сквозные сценарии

Сценарии проверяют уже заданный смысл. Они не навязывают protocol или schema.

| Событие | Поведение ELIOT | Доказательство/результат |
|---|---|---|
| Новый WorkScope без Git | Bootstrap Scanner строит provisional scope, доступные surfaces и gaps | Agent получает basic orientation; unknowns видимы |
| Agent не знает, что искать | Push по world/task cues, затем Dreamer Orientation | Relevant history/relations с provenance, а не generic search dump |
| Agent пишет плохо типизированное observation | Capture как Observation Candidate, curation позже | Source не теряется и не получает ложный status |
| Dreamer предлагает ложный merge или procedure | Result остаётся candidate либо обратимой derived projection; source, dissent и undo path сохранены | Нет скрытого epistemic promotion; ошибка становится curation evidence |
| Agent работает, но перестал писать observations | Watchdog сопоставляет workspace activity и Interaction Heartbeat | Gap, resync, reduced Governance Profile, Human warning при persistence |
| Два agents расходятся | Concilium отделяет evidence/frames, запускает discriminative audit | Provisional choice + preserved dissent/revision trigger |
| Большой swarm аудирует проект | Durable work graph, bounded micro-audits, challenge/synthesis/verify stages | Unique coverage, Evidence Lineage, gaps и partial results |
| Agent повторяет известный failure | Exact fingerprint требует new evidence/probe; semantic match предупреждает | Prevented repeat или false-activation learning |
| Guardrail создаёт false block | Governed Challenge и Recoverable Deviation при отсутствии Hard Boundary | Outcome меняет rule/negative memory |
| Poisoned memory обнаружена поздно | Revoke source influence through dependency closure; quarantine affected views | History сохранена, current support снят, clean re-evaluation |
| Prompt injection приходит через Dream query/document/tool definition | Content остаётся data, effects bounded, Watchdog получает security signal | Нет скрытой authority/secret exfiltration; source lineage сохранена |
| Optional Module падает | Supervisor локально деградирует, restart/rebuild/quarantine | Kernel и независимая работа продолжаются |
| Governor app падает, Kernel жив | New authority/effects stop; fencing, ORS, Recovery View and restart remain | No split brain; reconciliation before resume |
| Queue/storage pressure | Backpressure, shedding, Control Reserve, poison item quarantine | No false acceptance; control and recovery survive |
| Repair повторно не работает | Doctor меняет hypothesis/route, исчерпывает budget и escalates | No restart storm; Problem history and next action remain |
| Long session compacted/restarted | Checkpoint goals, rivals, commitments, losses and State Fence | Reconstruction from inheritance, no resurrection killed plan |
| Model/harness заменён | Public inheritance transfers; competence/context profiles requalified | Same commitments/evidence, no inherited tacit confidence |
| Verifier недоступен | Work may continue under explicit uncertainty | No VERIFIED_COMPLETE for dependent acceptance item |
| Human пропустил notification | Attention remains active; channel/owner escalates | Acknowledgement separate from resolution |
| Initial setup finds untrusted executable | Metadata probe only; no secrets/elevated authority before confirmation | Capability remains discovered, not trusted |
| Privacy erasure requested | Purge current/projections/ORS/backups/provider copies; update purge ledger | Restore cannot resurrect data |
| Backup restore after failure | Isolated restore, integrity/purge/revocation/epoch checks, separate cutover | No old leases, poisoned influence or stale authority |
| Canonical migration interrupted | Resume from checkpoint or rollback isolated copy; normal authority bounded | Cognitive inheritance preservation proof and migration receipt |
| ELIOT code conflicts with Architecture | Self-model exposes conformance gap; Dreamer/Watchdog provide brief | Fix Implementation or explicit Architecture change, never hidden drift |
| Новый experimental Module нужен во время активной работы | Capability получает isolated contour, independent proof, replay/shadow/canary; active generation остаётся immutable | No unproven effect on live task; reversible promotion/rollback receipt |
| Swarm реализует несколько независимых Modules | Contract/Evidence wave фиксирует interfaces; workers получают bounded work units; integration выполняет отдельный owner | Module proofs + affected Edge proofs + Product Pulse, without shared mutable plan |
| Все local Module tests зелёные, но Product Pulse падает | Promotion останавливается; Watchdog фиксирует development drift, Concilium/Mechanism Review пересматривает owner, contract или hypothesis | Local PASS не маскирует product regression; новый discriminator привязан к real path |
| Agent Work Unit не помещается в Safe Operating Envelope route | Task decomposed, compiled projection or different qualified route; Module size itself не объявляется нарушением | Decision-relevant context and reasoning margin preserved without universal size ceiling |
| Meta proposes optimization after stack changed | Candidate becomes stale outside validity scope | New canary before reuse; old result remains historical evidence |

---

# A16. Основные архитектурные решения

## A16.1. Decision anchors

Это навигационный индекс. Полный смысл, rationale и conflict behavior находятся в соответствующем разделе; краткая строка не является второй редакцией решения.

| ID | Класс | Решение |
|---|---|---|
| `ARCH-INTENT-01` | Invariant | Намерение выше буквального соблюдения |
| `ARCH-CONCIL-01` | Invariant | Dissent и falsification важнее количества согласных |
| `ARCH-DEV-01` | Contract | Working vertical spine before broad hardening |
| `ARCH-CORE-01` | Invariant | Understanding continuity first |
| `ARCH-CORE-02` | Invariant | Four planes, one governed loop |
| `ARCH-HELP-01` | Invariant | ELIOT снижает когнитивную и операционную нагрузку |
| `ARCH-ROLE-01` | Invariant | Observation, interpretation, authorization и verification разделены |
| `ARCH-ROLE-02` | Invariant | Responsibility следует компетенции и типу ошибки |
| `ARCH-AUTH-01` | Invariant | Authority is explicit, scoped and fenced |
| `ARCH-MOD-01` | Invariant | Small living Kernel; local module failure does not kill the system |
| `ARCH-MOD-02` | Contract | Depth grows through independently testable micro-modules; physical size/form remain empirical |
| `ARCH-PORT-01` | Invariant | Organs and execution contours are replaceable; public inheritance transfers, tacit strategy is requalified |
| `ARCH-SCOPE-01` | Invariant | Scope before reuse |
| `ARCH-MEM-01` | Contract | Capture first; ELIOT organizes later |
| `ARCH-MEM-02` | Invariant | Semantic fallibility is recoverable through forward revision |
| `ARCH-MEM-03` | Invariant | Derived memory preserves evidence and lineage |
| `ARCH-MEM-04` | Invariant | Retrieval is not reinforcement; forgetting is not belief revision |
| `ARCH-LIFE-01` | Invariant | No semantic teleportation between observation, interpretation, authority and proof |
| `ARCH-EPI-01` | Invariant | Reality corrects; epistemic positions remain defeasible |
| `ARCH-EPI-02` | Contract | Theories earn and lose weight through outcomes |
| `ARCH-UND-01` | Invariant | Load-bearing understanding has a public inspectable form |
| `ARCH-UND-02` | Contract | Causal understanding is tested by discriminative prediction and outcomes |
| `ARCH-GROUND-01` | Contract | Models are tied to tools, graphs, artifacts and verifiers |
| `ARCH-SELF-01` | Contract | ELIOT maintains evidence-linked self-knowledge without self-certification |
| `ARCH-CTX-01` | Contract | Decision sufficiency before context optimization |
| `ARCH-CTX-02` | Contract | Observable state drives proactive memory |
| `ARCH-CTX-03` | Contract | Decision locality is route-profiled |
| `ARCH-CTX-04` | Contract | Retrieval proposes candidates; Context Compiler admits influence |
| `ARCH-ATTN-01` | Contract | Critical Attention is state, not a message |
| `ARCH-SKL-01` | Contract | Skills are short, intent-dense and challengeable |
| `ARCH-WDG-01` | Contract | Independent supervision |
| `ARCH-WDG-02` | Contract | Watchdog supervises preservation of declared intent, observable outcomes, security and recovery |
| `ARCH-DRM-01` | Invariant | Dreamer is an AI service, not an owner or authority |
| `ARCH-DRM-02` | Contract | Dreamer expands hypothesis space and orientation |
| `ARCH-DRM-03` | Contract | Dreamer agents/swarm are human-governed by budget and policy |
| `ARCH-DRM-04` | Invariant | Researcher acquires, Dreamer interprets, Governor governs |
| `ARCH-ACT-01` | Contract | Effect defines impact and authority |
| `ARCH-SWM-01` | Contract | Swarm is a bounded, context-minimal staged evidence pipeline |
| `ARCH-SWM-02` | Contract | Swarm coordination is durable, idempotent and epoch-fenced |
| `ARCH-LONG-01` | Invariant | Long work lives in durable state |
| `ARCH-FIN-01` | Invariant | Completion is proof-bearing; other finish states remain explicit |
| `ARCH-HUM-01` | Invariant | Human keeps value authority and practical control |
| `ARCH-SEC-01` | Invariant | Assume compromise; preserve control and recovery |
| `ARCH-SEC-02` | Invariant | One governed canonical transition path |
| `ARCH-SEC-03` | Invariant | Influence remains origin-bound and revocable |
| `ARCH-SEC-04` | Invariant | Model output remains candidate until governed transition |
| `ARCH-PRIV-01` | Contract | Erasure propagates and is not undone by restore |
| `ARCH-RES-01` | Invariant | Fail locally, recover globally |
| `ARCH-RES-02` | Contract | Self-repair is bounded and verified |
| `ARCH-RES-03` | Invariant | Restore/migration cannot resurrect invalid state |
| `ARCH-ORD-01` | Invariant | Parallel where independent; ordered where causal |
| `ARCH-OBS-01` | Invariant | Logs, metrics, audit and reports are distinct |
| `ARCH-RES-04` | Invariant | Degradation is visible and local |
| `ARCH-RES-05` | Contract | Recovery produces reusable knowledge |
| `ARCH-LEARN-01` | Invariant | Learning changes external inheritance through grounded outcomes |
| `ARCH-META-01` | Contract | Self-improvement is advisory, isolated, evidence-driven and falsifiable |
| `ARCH-ECON-01` | Contract | Cost is an authority boundary |
| `ARCH-DEV-02` | Contract | Depth grows through independently testable layers, edge proofs and Product Pulses |

## A16.2. Anti-patterns

```text
RAG, summary, graph или context size, выданные за understanding;
правило, соблюдаемое ценой Intent и working product;
ссылка на Intent как оправдание скрытого bypass без evidence, owner и review;
число agents, votes или repeated lineage, выданные за truth;
одна модель/vendor как незаменимый cognition owner;
agent, обязанный администрировать ontology вместо основной работы;
semantic error, трактуемая как необратимая порча всей памяти;
summary/compaction без source, losses и undo path;
retrieval/repetition как reinforcement;
giant context dump или silent truncation;
Dreamer/Watchdog/Synthesis Agent как authority;
Dreamer curation, незаметно меняющая epistemic support, source history или policy;
Researcher acquisition и Dreamer synthesis, слитые в один неуправляемый owner;
Skills/prompts/filter как единственная security/enforcement boundary;
security, предполагающая непробиваемую броню;
remote Dreamer как доступ к local DB/tools;
несколько canonical owners или direct storage bypass;
optional Module failure, кладущий Kernel;
retry/restart loop без нового evidence, budget и escalation;
recovery spool как вторую semantic memory;
restore, возвращающий revoked influence, deleted data или old authority;
notification/ack/restart как resolution;
self-improvement без owner, canary, proof и rollback;
tests, phases и reports как замена реальному vertical spine;
первый vertical spine, выданный за завершённый four-plane ELIOT;
фиксированный размер/число Modules как конституционный закон;
source module, package, process и service, ошибочно сведённые к одной границе;
unbounded shared-chat swarm или whole-project context для каждого worker;
локально зелёные Module tests без affected Edge proof и Product Pulse;
непроверенный prototype, сразу получающий live authority или hot-path influence;
active generation, переписывающая себя без candidate, replay/shadow/canary и rollback;
append-only normative documentation и hidden precedence;
конкретный vendor/benchmark/mechanism как вечный invariant.
```

## A16.3. Итоговая формула

```text
ELIOT = durable governed cognitive inheritance
      + plural scoped understanding corrected by reality
      + proactive attention and route-specific Active Views
      + Harness for agents, tools, swarm, authority and proof
      + Dreamer for bounded synthesis, orientation and research
      + Watchdog/Doctor for supervision, recovery and security
      + Concilium, practical trials and advisory Meta learning
      + micro-modular layered capabilities with isolated prototype promotion
      + context-minimal agent pipelines, independent proofs and Product Pulses
      + Human value authority and control
      + a small resilient Kernel that survives local failure.
```

ELIOT успешен не тогда, когда хранит больше данных, пишет больше правил, создаёт больше Modules или запускает больше agents. Он успешен, когда человек и agent могут восстановить достаточное понимание, выполнить ограниченную и осмысленную работу, проверить Module и реальные edges, увидеть product outcome, пережить ошибку и улучшить следующую итерацию без переписывания всей системы.
