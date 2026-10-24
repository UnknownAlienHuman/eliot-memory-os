# Eliot V3 — решения по исходным требованиям и границы охвата

**22 октября 2026. Приложение к [итоговому аудиту](AUDIT.md), не runtime registry и не перечень разрешений.**

Эта карта заканчивает сверку доступных предложений для переписывания. Она не выдаёт решение «не переносить» за чтение исходников и не объявляет все источники проверенными. Старые подробные reading ranges остаются в [карте 0.23](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/41c2291f3b968ddbb2690b2f4be79e1677730de7/docs/v3/AUDIT-MAP.md).

## 1. Корпус и предел проверки

| Материал | Фактически доступно и использовано | Что не утверждается |
|---|---|---|
| V1 Canonical Master | Полный текст до §40 прочитан в подготовке 0.24; цели и старая governance doctrine разделены | Это не полное чтение всего V1 или повтор всех его experiments |
| Understanding Layer v1.4 и V2 нормы | Ранее разобранные Parts A/C/D/E и конкретные normative sections; immutable ссылки в прежнем аудите | Все нормы V2 и все ~2.6 млн физических строк не перепроверены |
| Claude revision 4, `eliot-documentation-audit(1)(1).md` | Полный текст доступен; каталог, 63 якоря, восемь границ, предложения реализации/переноса и заключительные отступления сопоставлены | Его оценки LOC/скорости/полноты не новые измерения и не решения владельца |
| `ELIOT_AUDIT_2026-10-08_v9(1).md` | Получен полный текст, включая T32–T37; T01–T37 получили переносимое решение ниже | Все первичные code paths не запускались и не перечитывались на текущем main |
| `ELIOT-Swarm-AUDIT-2026-10-06(2).md` | Получен полный текст; логика controller/практики, сокращение, потеря локальных материалов и рекомендации сопоставлены | Исторические provider особенности и цифры не current deployment facts |
| Аудит относительно `/docs/architecture`, 31.08.2026 | Полный текст; конкретные gaps отделены от похвалы строгой proof architecture | Его нормативный выбор не принят автоматически для V3 |
| `ELIOT-LLM-PROBLEMS-2026-10-07.md` | Полный текст; failure classes сопоставлены с путями продукта и процессом разработки | Пересказ прежнего инцидента не заново воспроизведённый дефект |
| Локальный пакет 0.24 | Прочитан и содержательно включён: continuation, method consumer, transfer, MemP/MentisDB | Его patch не объявляется применённым к старым нормативным файлам |
| Релиз `audit-2026-10-16-incomplete` | Metadata и перечень assets подтверждены | ZIP и 968 entries не прочитаны; manifest не semantic review |
| `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` | Только ссылки на него в Claude; прямые поиски не дали полного текста | Другой отчёт не подставляется под его имя |

Недоступные последние два источника остаются **исключением из основания заключения**. Для исчерпывающего утверждения о всём архивном корпусе они нужны; для выбранного connected rewrite нельзя бесконечно выдавать их отсутствие за запрет разработки. Остальная работа разделена на конкретную реализацию и возможное уточнение источников, не смешана в один «процент готовности».

## 2. Поимённая сверка 63 якорей Claude

Источник названий/кратких требований — §6.1 приложенного Claude revision 4. Правая колонка — решение данного аудита. Это проверка смысла и осознанных расхождений, а не заявление о выполнении старой нормы буквально или о готовом коде.

| Якорь | Требование в перечне Claude | Итоговое решение V3 |
|---|---|---|
| INTENT-01 | намерение выше буквы | Сохранить назначение выше ритуала; конфликт нормы и цели явно исправлять, не маскировать. |
| CONCIL-01 | несогласие важнее голосов | Альтернативы, основания и различающее наблюдение; один участник допустим, голосование не доказательство. |
| DEV-01 | сначала работающий срез | Поставлять связанное поведение. Это не запрет параллельных независимых работ. |
| CORE-00 | работа накапливается | Наблюдения работы остаются в памяти. Обязательный урок или объяснение отсутствия урока на каждом finish убрать. |
| CORE-01 | непрерывность понимания | Адресная continuation текущей задачи/ветки плюс новые события; host compaction не второй task manager. |
| CORE-02 | четыре плоскости, один цикл | Сохранить роли цикла; плоскости не являются обязательными процессами. |
| HELP-01 | снижать нагрузку | Штатный захват и малый доменный интерфейс; произвольный потолок восемь инструментов не критерий пользы. |
| ROLE-01 | наблюдение, толкование, полномочия и проверка разделены | Наблюдение, интерпретация, permission и acceptance различаются. Приёмка внешней задачи у host/controller. |
| ROLE-02 | ответственность по компетенции | Данные, исполнения и решения имеют своих фактических владельцев, не дублирующие власти. |
| AUTH-01 | полномочия явны | Конфигурация владельца и реальные host permissions; не отдельная grant/approval платформа на каждую запись. |
| MOD-01 | маленькое живое ядро | Малый связанный service. Rust task не изоляция process abort; независимый supervisor вне daemon. |
| MOD-02 | глубина добавляется модулями | Добавлять нужную функцию в модуль; actor/job/hook не обязательная классификация любого helper. |
| MOD-03 | у состояния один владелец | Один Store writer; views читают его данные. Не отдельный guard registry ради этого правила. |
| PORT-01 | органы заменяемы | Настоящие adapters, network SDK и export; не универсальный backend framework. |
| SCOPE-01 | область прежде повторного использования | Источник отдельно от reuse scope; проекты и общие методы фильтруются до top-k. |
| MEM-01 | захват прежде организации | Сохранить permitted raw до модели, точность/полноту захвата обозначить. |
| MEM-02 | ошибки памяти исправимы | Редакция конкретного item и история; current row не вечная append-only проекция. |
| MEM-03 | производное хранит источники | Реальные адресуемые источники и версия; модель не создаёт source contents одним ID. |
| MEM-04 | извлечение не подкрепляет | Retrieval не support. Rank допускает relevance/recency, но не выдаёт популярность за истинность. |
| LIFE-01 | нет телепортации статусов | Причина и автор изменения в owning record/history, без общего автомата всех видов памяти. |
| EPI-01 | позиции опровержимы | Разрешать адресную группу по времени/условиям/перспективе; latest или голова цепочки не универсальная истина. |
| EPI-02 | вес по исходам | Наблюдаемые результаты уточняют полезность; источники/коррекции уточняют факты, не только verifier. |
| EPI-03 | разведка не подтверждает себя | Исключить самоудостоверение. Два источника не обязательный допуск единственного полезного эпизода. |
| EPI-04 | покрытие требует знаменателя | Называть examined scope и gaps; пустой top-k не универсальное отсутствие. |
| UND-01 | понимание выражено публично | Хранить объяснение и отвергнутые варианты, а не скрытый reasoning transcript или сертификат понимания. |
| UND-02 | причинность проверяется предсказанием | Ожидание до действия и последующее наблюдение; dependency graph не causal experiment. |
| GROUND-01 | опора на артефакты | Конкретные source spans, ресурсы и реальные изменения; aliases не exact identity. |
| SELF-01 | ELIOT знает себя | Eliot читает собственные документы/данные теми же средствами; status отражает реальные jobs/results. |
| CTX-01 | достаточность прежде размера | Основание и существенное исключение упаковываются вместе; handles раскрывают детали. |
| CTX-02 | проактивность от наблюдаемого | Триггеры от реальных доступных host/source events, не модель перед каждым событием. |
| CTX-03 | доставка рядом с решением | Доставка на фактической границе решения; PreToolUse advice не отменяет уже выбранное действие. |
| CTX-04 | поиск предлагает, сборщик допускает | Candidate selection и смысловая применимость; не обязательный permission score или запись лога до ответа. |
| ATTN-01 | обязательство — состояние | Обязательство — ordinary memory state; показ/ack не resolution и не сообщение на каждом входе. |
| SKL-01 | Skills короткие | Полезный компактный метод + раскрытие; сорок строк не универсальный предел. |
| WDG-01 | независимый надзор | Один реальный независимый observer в active interval. Hook relay сам не видит hung daemon. |
| WDG-02 | надзор за исходом, а не за церемонией | Различать heartbeat, progress и outcome; не читать prose как достоверный процессный сигнал. |
| DRM-01 | Dreamer — не владелец | Модель предлагает; приложение применяет обычные revisions. Provisional advice не ждёт promotion bureaucracy. |
| DRM-02 | Dreamer расширяет гипотезы | Объяснения, alternatives, gaps и следующий полезный вопрос остаются предметом интерпретации. |
| DRM-03 | вычисления Dreamer под человеком | Configured finite work/cost/routes; manual/idle/due режимы не отдельные scheduler engines. |
| DRM-04 | добыча ≠ толкование | Acquisition отдельно от interpretation; Research входит в полный scope, не удаляется решением аудитора. |
| ACT-01 | эффект определяет полномочия | Host/controller исполняет и проверяет actual permissions. Память советует; regex команд не второй execution governor. |
| SWM-01 | рой — ограниченный конвейер | Рой остаётся controller/host; память не владеет повторно task acceptance. |
| SWM-02 | координация переживает агентов | Долговечная работа Eliot сохраняется в job; вся peer-координация не импортируется. |
| LONG-01 | долгая работа живёт в БД | События, continuation и jobs переживают сессию; current task определяется адресно. |
| FIN-01 | готово только с доказательством | Не выдавать частичный исход за готовность. Второй finish owner и выдуманный proof из памяти убрать. |
| HUM-01 | человек управляет | Прямые status/inbox/configure/correct/erase/backup/restore; approval не обязателен для обычного read. |
| SEC-01 | предполагать взлом | Отделить данные от инструкций, сохранять provenance и capture exclusions; не quarantine всей полезной памяти. |
| SEC-02 | один путь записи | Один application write path и стандартные OS/DB границы; это не sandbox против unrestricted same-user process. |
| SEC-03 | влияние привязано к источнику | Адресный пересмотр реальных зависимостей; AND/OR не угадываются по числу citations. |
| SEC-04 | вывод модели — кандидат | Разбирать реальный model output; schema check не proof истины и не причина запрещать условную подсказку. |
| PRIV-01 | стирание не воскресает | Known deletion replay и controlled purge; неизвестная история обозначается при явном owner restore. |
| RES-01 | падать локально | Локальный отказ нужной операции; отдельные runtime-процессы только по реальной failure boundary. |
| RES-02 | самоисправление ограничено | Не повторять бесполезный конкретный repair; не блокировать всю диагностику конфигурации. |
| RES-03 | восстановление не воскрешает | Известные удаления применяются; старые external jobs не replay автоматически. |
| ORD-01 | параллельно где независимо | Порядок зависимых изменений и параллельность независимых; нет project-wide oldest-head барьера. |
| OBS-01 | журналы ≠ метрики ≠ аудит | Логи, метрики и primary history различаются; optional telemetry не меняет известный effect result. |
| RES-04 | деградация видима | Сообщить конкретную недоступность, сохранив остальную пользу; не общий availability certificate. |
| RES-05 | восстановление даёт знание | Сбой может дать полезный случай для будущего; каждый restart не обязан создавать новый урок. |
| LEARN-01 | обучение через внешнее наследие | Изменённый урок/метод действительно читается следующим consumer; не лестница влияния ради формы. |
| LEARN-02 | локально быстро, глобально — с доказательством | Automatic provisional transfer с условиями. Широкая эффективность не следует из shared flag или двух повторов. |
| META-01 | самоулучшение — совет | Исправить исходную формулировку: не только советы человеку. Подключённые методы/параметры могут обновляться автоматически; code changes через developer. |
| ECON-01 | стоимость — полномочие | Учитывать actual/unknown usage и настраиваемую работу; budget не подставляется как measured consumption. |
| DEV-02 | глубина — проверяемыми слоями | Полезные законченные пути и явный full scope; текущий owner code/minimal-Clippy/tests-later без новой тестовой платформы. |

### Восемь Hard Boundaries

Исходные названия — Claude §5.8 со ссылкой на A0.3. Сохраняется запрет указанной ошибки; механизм меняется по выбранным владельцам, без восьми новых сервисов.

| Исходная граница | Решение V3 и предел |
|---|---|
| Скрытое создание или расширение полномочий | Model text не меняет user/config/tool permissions; реальный эффект остаётся у host/controller |
| Скрытая подмена цели пользователя | Сохранить исходную цель и явные поправки; summary и method proposal не заменяют её молча |
| Неотслеживаемый необратимый или внешний эффект | Сохранить actual execution reference/result; unknown отдельно, без слепого replay |
| Ложный VERIFIED_COMPLETE | Память не фабрикует success и не принимает внешнюю задачу вместо её владельца |
| Скрытое переписывание происхождения или истории | Реальные originals и редакции, адресуемый historical open; hash не доказательство смысла |
| Возврат отозванного влияния после восстановления | Применить известные withdrawals/deletions; неизвестную историю обозначить при explicit owner restore, не обещать невозможное |
| Второй неуправляемый владелец или путь записи | Один application Store writer; native DB/OS boundary, без второй semantic database |
| Секреты за границей приватности | Configured capture exclusions и allowed routes на реальной передаче; не объявлять фильтр секретов безошибочным |

Это осознанное сопоставление, не буквальное сохранение предложенных Claude finish/approval/effect-log механизмов. Правильная полезная операция не должна ждать сертификата, который сам не создаёт нужной гарантии.

## 3. Все T01–T37 из v9: что относится к переписыванию

Левая часть — историческая находка v9, не новый результат запуска. Правая часть — что делать в V3. «Не переносить механизм» не означает, что старый дефект исправлен в V2.

| ID | Исторический предмет | Решение для нового продукта |
|---|---|---|
| T01 | Неверный разбор rust-toolchain.toml | Использовать parser формата у реальной build-интеграции, не новую конфигурационную эвристику |
| T02 | Ошибка чтения override превращена в default | Отличать missing optional config от ошибки чтения выбранного значения |
| T03 | Blob helper подтверждает не сохранённые bytes | Сначала реальная запись, затем адресный readback; receipt не содержимое |
| T04 | Reservation подменяется worker claim | Не импортировать оба старых аппарата; обычный finite job хранит своего исполнителя |
| T05 | Defer-only Observe | Capture соединить с primary Store; недоступная отдельная операция не стоп остальных |
| T06 | Скопированный token переживает смену роли | Реальные host/control permissions, не независимая authority-копия в памяти |
| T07 | Переход через промежуточную роль теряет ограничение | Не вводить свою роль-платформу; исполнение и acceptance оставить внешнему владельцу |
| T08 | Актуальный accessor отдаёт legacy relation | Чтение адресной текущей записи без compatibility facade |
| T09 | Snapshot hook уже подключён | Не создавать заново; учитывается исправленный статус источника |
| T10 | Requalification стирает чужой failure | Изменять состояние конкретного target; независимые проблемы сохраняются |
| T11 | Неоднозначное legacy становится Available | Unknown capability не рабочий route; не выключать остальные |
| T12 | ClientHello policy не доказательство её происхождения | Использовать configured реальный маршрут; не восстанавливать три реестра ради handshake |
| T13 | Nonce в argv против старой нормы | Не заявлять доказанную утечку; credentials не кладутся в model context/ненужные командные строки |
| T14 | Watchdog applicability есть, publisher не соединён | Один actual observer и reader его состояния, не новый sensor registry |
| T15 | Повтор counted ID повышает threshold | Считать уникальные исходные события/попытки, не длину списка |
| T16 | Diagnostic brief остаётся write-only | Нормальный status/context читает полезные сведения из owning data |
| T17 | Trigger возвращается раньше своего gap report | Локальный исход и useful partial result не теряются за общей ветвью |
| T18 | Production log-window всегда пуст | Подавать настоящий сохранённый вход; пустой carrier не анализ |
| T19 | Proposal identity есть, privacy input нет | Настоящие source/route constraints в момент передачи, не ещё один identity object |
| T20 | Positive Testd producer не подключён | Использовать наблюдаемый результат настоящего инструмента; fixture не effect |
| T21 | Store теряет sub-minute timezone | Сохранять предоставленную точность/offset; unknown не округлённая выдумка |
| T22 | MUST_PROVE_ZONES не mandatory denominator | Coverage сообщает фактические checks/scope; policy label не полнота |
| T23 | Пять Observe variants defer-only при внутреннем owner | Один реальный capture entrypoint→writer; не полный V2 DTO inventory |
| T24 | OpenCode default уходит в legacy executable | Первый поддержанный host route выбран явно; no permanent legacy fallback |
| T25 | Packet работает, State flight отсутствует | Сохранить полезный packet; current continuation адресно связать с source events |
| T26 | Material gate есть, публичного Act caller нет | Внешний Act остаётся host/controller; не копировать gate в Memory OS |
| T27 | Coordinate компоненты есть, flight отсутствует | Рой/координация вне памяти; Concilium как разбор scoped вопроса |
| T28 | Verify только admit | Actual tool result отдельно от acceptance входа; не изготовлять proof |
| T29 | Prelude helpers не на live boundaries | Штатный host hook вызывает реальный capture/context, а не standalone helper в отчёте |
| T30 | Finish path жив, binding неполон | Не объявлять Finish отсутствующим; в V3 внешний owner и точные task/outcome references |
| T31 | Cold-start machinery без live caller/durability | Demand-start + primary read + реальная фоновая ориентация, не ещё один readiness lifecycle |
| T32 | Backup owners существуют, нет transport | V3 один Store и выбранная обычная backup операция; не достраивать старую распределённую схему |
| T33 | Maintenance composition fail-closed unpublished | Настоящий configured worker; отсутствие optional maintenance не выключает read/capture |
| T34 | Research domain есть, source unadmitted; non-success теряется | Реальный adapter и сохранённый terminal failure/partial; недоступность источника не no-findings |
| T35 | Runner/providers не поданы существующему state machine | Соединить настоящий executor; не ещё один runner/state engine |
| T36 | ORS durable event есть, receiving owner не принимает | Один primary capture→job→reader; различать сохранение и интерпретацию без ORS-клона |
| T37 | Bridge forward/recovery есть, дальнейший consumer/replay разорван | Не заявлять отсутствующим весь Bridge; подтверждать реально сохранённый input и продолжать с того же ID |

Сохранены самоисправления v9: отсутствие карты зависимостей, обязательность нового registry, тесты как установленная главная причина, blanket file limits и ряд выводов по счётчикам были отозваны или ограничены. Старые критерии ремонта V2 не становятся нормой переписывания. Аудит проекта не меняет сам code/issue state V2.

## 4. Доноры: охват отдельно от выбора

**Код** означает конкретные функции/callers, не полный review продукта. **Документы** означают документацию/статью, не runtime. **Не пересверен** означает, что сопоставимый source-level разбор не установлен в поддерживаемом корпусе. Решение не использовать продукт может быть принято по отсутствию потребности, без выдуманного утверждения о его качестве.

| D | Источник | Уровень | Итог для V3 |
|---|---|---|---|
| 01 | MemMachine | Код | Взять episode/source expansion и понятное grouping; не messages×categories/oldest prefix или второй backend |
| 02 | MemPalace | Не пересверен | Не dependency; source-event identity уже решена первичными данными |
| 03 | Subcog | Код | Взять independent retrieval/fusion; не score=confidence и не отдельный HOT/WARM/COLD lifecycle |
| 04 | MemOS local plugin | Код | Изученные L2/gain ограничены; не переносить causal claims из prior/association |
| 05 | Claude Code memory/tool search | Документы | Штатный поддержанный host интерфейс; установленную версию проверить при реализации |
| 06 | ClawVM | Не пересверен | Не dependency; compaction остаётся host, memory хранит источники |
| 07 | Pichay / demand paging | Не пересверен | Не отдельная paging ОС; раскрытие решено обычным open |
| 08 | Graphiti | Код | Временные различия и targeted contradictions; не graph runtime/managed Zep |
| 09 | Hindsight | Код | Facet update, question views, delta и исключение injected echo; не полный layer stack |
| 10 | Current EverOS | Код | Реальные foresight consumers, группы и coverage; не scoped full scan |
| 11 | Historical EverMemOS | Документы | Идеи episodes/foresight; не приписывать исторические scores нынешнему коду |
| 12 | Cloudflare managed Agent Memory | Не пересверен | Не выбранный backend; не обещать бесплатную библиотеку вместо сервиса |
| 13 | Cloudflare Agents SDK Sessions | Не пересверен в итоговом корпусе | Host branch semantics полезны как направление; не перенос Cloudflare runtime на локальный Rust |
| 14 | SurrealFS | Не пересверен | Не dependency; конкретные source/version handles уже выбраны |
| 15 | MentisDB | Код выбранных функций, 0.24 | Method id/revision/body lookup; не binary store/signature/log-diff платформа |
| 16 | LangMem | Код | Separate background work, trajectory proposals, обработанный keep; не второй scheduler |
| 17 | Letta Code | Код | Continuation отдельно от learning, actual callers; не второй host/context manager |
| 18 | Archived Letta V1 | Не пересверен | Не клонировать historical server вместо выбранных current механизмов |
| 19 | Nocturne Memory | Код | Stable node/alias и useful disclosure clue; не persona/mandatory boot doctrine |
| 20 | Mem0 OSS | Код | Реальный extraction caller; сохранить tools/ошибки, не embedding-before-primary |
| 21 | Historical OpenMemory MCP | Не пересверен | Не выбранный runtime; historical/current identity не смешивать |
| 22 | OpenMemory session CLI | Не пересверен | Не dependency; реализовать свой реальный import/export, не roadmap |
| 23 | Cavira LongMemory | Не пересверен | Не dependency; exposure/supersession уже имеют конкретный owner |
| 24 | ripgrep | Не пересверен как донор кода | Использовать существующий настроенный инструмент, не переписывать библиотеку |
| 25 | ast-grep | Не пересверен как донор кода | При реальной structural query использовать внешний tool; не собственный parser |
| 26 | SCIP | Не пересверен как донор кода | Формат/producer подключать по нужде; первый структурный источник D47 |
| 27 | GitHub Copilot Memory | Не пересверен | Не зависимость и не доказанный публичный алгоритм; текущий путь не ждёт его |
| 28 | Docling | Официальные документы, 22.10 | Выбран внешний converter для document/media input; не встроенная memory platform |
| 29 | Docling Core | Официальные документы, 22.10 | Сохранить реальные hierarchy/provenance, не flatten всего в строку |
| 30 | DocETL | Не пересверен | Не нужен workflow engine; simple finite transforms в existing jobs |
| 31 | Vector / VRL | Не пересверен | Не вводить DSL ради capture; отдельная ingestion-потребность может изменить решение |
| 32 | Kreuzberg v4 LTS | Не пересверен | Не параллельный parser по умолчанию; альтернатива при конкретном недостатке Docling |
| 33 | Current Kreuzberg | Не пересверен | Не наследовать свойства LTS; не выбран автоматически вторым parser |
| 34 | Cedar | Не пересверен | Не нужен baseline enterprise policy engine |
| 35 | OPA | Не пересверен | Не нужен второй policy owner |
| 36 | redb | Не пересверен как новый донор | Не вторая semantic DB; bounded spool обычными файлами |
| 37 | duroxide | Не пересверен | Не выбранный workflow runtime; finite job уже определён |
| 38 | Flawless | Не пересверен | Unknown-effect handling учтён, новый runtime не нужен |
| 39 | FoundationDB testing | Не пересверен | Не prerequisite переписывания и не новая тестовая платформа |
| 40 | Wasmtime | Не пересверен | Не baseline plugin/runtime; только будущая конкретная недоверенная extension |
| 41 | SurrealDB Agent Memory / Spectron | Документы | Отдельный application tier, не встроенная семантика SurrealDB; не dependency |
| 42 | MAGMA | Код и статья | Отношения под недостающий ответ, не full scans/keyword veto/multi-graph runtime |
| 43 | A-MEM | Код и статья | Actual indexed evolution и IDs; не копировать positional update и neighbor-after-top-k |
| 44 | Harness2 | Код и статья | Два improvement loops через existing owners; baseline/keep, не benchmark workload |
| 45 | claude-mem | Код | Host capture, persistent input, stable delivery; не весь Bun/SQLite/provider runtime |
| 46 | OpenHands Software Agent SDK | Код | Actual tool/result boundaries и view поверх events; не пустой summary как успех |
| 47 | codebase-memory-mcp | Код выбранных handlers | Настроенный structural tool, не embedded parser/SQLite/daemon/UI |

Уровни: 17 позиций с конкретным кодом, 5 с документами/статьёй, 25 без сопоставимого пересмотра. Это учёт представленных разборов, не 17 полностью изученных продуктов или процент готовности. Hy-Memory, V1/V2, controller и Research учитываются отдельно. MemP остаётся отдельным исследовательским источником: actual workflow→prompt→outcome→update прочитан в подготовке 0.24; его benchmark не запускался.

Дополнительные имена из Claude (basic-memory, mcp-memory-service, дополнительные host plugins и другие кандидаты) не скрыто объявляются изученными. Для текущего решения другие memory stores не выбираются, а поддержка дополнительных host interfaces выполняется адаптерами при реализации. Неполученный полный union архивного P/S-реестра остаётся пределом источников; число библиографических строк не доказывает их проверку.

## 5. Из исследований в реализацию

| Прежний открытый вопрос | Решение в итоговом аудите | Что реально написать позже |
|---|---|---|
| Current work вместо похожего прошлого | Адрес project/session/task/branch и свежие события | Reader continuation и обычные сохранённые updates |
| Реальный consumer метода | Job хранит id/revision; builder открывает body | Prompt/config consumption в существующих модулях |
| Межпроектный перенос | Origin отдельно от reuse scope | Scoped find и генерация условного общего метода |
| Составные основания | Roles и необязательные группы существующих links; unknown не угадывается | Targeted dependency lookup/recompute, не общий ATMS |
| Не-кодовые источники | Native text + внешний Docling и реальные source locators | Конкретные converters/open сегментов, preserve raw |
| Первое включение | Local config, один instance, малый standalone supervisor + daemon + DB | Windows launch, IPC, lifecycle и файловые primitives |
| Модели и embeddings | Новый узкий `inference.text`/`inference.embed` у controller; Memory не копирует Task/Attempt или provider stack | Durable request/result/readback, unknown outcome и per-input vector mapping |
| Research | Один domain adapter через реальную configured task/tool surface | Request/result/source mapping, не второй research engine |
| Итоговая документация | Один смысловой baseline аудита; drafts переписать согласованно | Architecture — цель; Implementation — connected paths; Cognition — алгоритмы |

Оставшиеся пункты — реализация выбранной конструкции, а не разрешение снова плодить каталоги. Не заявляются работающий V3, успешный model/DB/Windows run, независимые субагенты или повтор всех прошлых тестов. Форматирование/ссылки документов проверяются отдельно от продуктового поведения. Существующие CI и main не меняются этим аудитом.

## 6. Inference boundary update — 2026-10-24

| Источник требования / находка | Сохранённый смысл | Отброшенное средство | Нормативное решение V3 | Статус |
|---|---|---|---|---|
| V1/V2 Dreamer, I9.1/I9.3/T12 | Конечная model-assisted интерпретация, bounded input, structured result, no permanent loop, model independence | Отдельный Dreamer process/ledger, Governor admission/lease chain и candidate ceremony для каждой обратимой правки памяти | Один Memory `job` выбирает exact recipe/input; controller `inference.text` выполняет one-shot model call; Memory decode/publication/context остаются у Memory | `DECIDED`, route не реализован |
| Controller `38db378c` Task/Attempt/Claude path | Exact prompt delivery, route/provider ownership, request identity и durable artifacts полезны | TaskSpec/requirement/Attempt/binding/review/acceptance для одного extraction request | Переиспользовать Operation/dedup/route/artifact owners в новом method без Task/Attempt semantics | `GAP` R-048 |
| Hy-Memory `6b0bd866` provider client | Простой configurable prompt→content/model/finish/usage shape | Blind retry after timeout/connection/408/429/5xх без idempotency/readback | Exact request сохраняется до I/O; ambiguous outcome остаётся unknown; retry только после proven non-admission/native readback | `DECIDED` |
| Embedding requirement | Query/document role, compatible space, independent result per input | Text-agent task или aggregate/zero-vector fallback | Отдельный controller `inference.embed` + Memory `EmbeddingClient`; derived fields only | `GAP` R-015/R-048 |
| User implementation direction | Реальная разработка прежде тестового онанизма | Speculative test platform и production shims ради placeholder tests | Connected production code; minimum build/Clippy per coherent increment; full suite after product implementation | `DECIDED` R-049 |

Полный разбор находится в [AUDIT §38](AUDIT.md#38-one-shot-inference-without-a-second-task-manager-or-a-second-provider-stack--10), активные implementation gaps — в [ANALYSIS-REGISTRY R-047–R-049](ANALYSIS-REGISTRY.md). Эта карта фиксирует происхождение решения; она не объявляет controller routes или V3 runtime реализованными.
