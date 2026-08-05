# ELIOT Memory OS — forensic-аудит записей, ошибок и истории проблем

Дата среза: 2026-08-05  
Репозиторий: `C:\Users\kleym\OneDrive\Documents\Rust\projects\eliot-memory-os`  
Канонический project key: `eliot-memory-os`  
Project ID: `87731db9-1e51-8fde-a4db-222705d7d03a`  
Основной анализируемый срез: revision/sequence `190/190`  
Предыдущий полный аудит: `reports/audit/ELIOT_FULL_PROJECT_AUDIT_20260805.md`, SHA-256 `F67BC20CFC5D08002E2F75422EE5AEEC17B33FFF4ACBD24BA21A3A2547BE02C7`

## 1. Итоговый вывод

Проблема Eliot сейчас не в отсутствии записей. Проблема в том, что полезные факты, тестовые nonce, исторические install-срезы, дубли, диагностические гипотезы и устаревшие состояния почти одинаково представлены как `active weak candidate`.

На срезе revision 190:

- найдено 54 ClaimCard; все 54 `weak`, `active`, `candidate_only=true`, `controller_reconciliation_required=true`;
- `supported=0`, `verified=0`, exact-evidence coverage `0`, verifier-link coverage `0`;
- все 54 claims имеют `belongs_to` к TaskContract, но восемь открытых TaskContract не содержат ни одной acceptance-ссылки;
- обнаружено девять TaskContract: восемь открытых `0/2` и один скрытый от task-candidate discovery `done_verified 2/2`;
- единственный найденный canonical VerifierRun проверяет разрешение одного receipt, а не весь заявленный fleet/doctor/hash/Git scope;
- обычный `eliot_recall_l0` всё ещё читает stale projection revision 82 и возвращает ноль handles, хотя canonical revision уже 190;
- `lifecycle_audit=true` видит revision 190, но ответ для 12 handles занимает 81,496 символов, из которых 78,899 — rank trace;
- `current_state` отдаёт только 50 из 54 claims и не предоставляет cursor;
- curation preview просканировал все 54 claims по их девяти task scopes и предложил ноль suppress/promote/archive действий;
- distillation видит 139 физических записей, все в `cold`, и также предлагает ноль действий;
- latest CodeCortex привязан к `C:\Users\kleym\AppData\Local\Eliot`, а не к Git-репозиторию;
- глобальные sleep/replay/verify reports показывают другой project ID `188b0b87-e50d-84c6-a968-61fb08d05d48`; replay verdict датирован 2026-09-08, то есть будущим относительно текущего среза;
- runtime daemon здоров, но это не означает, что memory retrieval, lifecycle, acceptance или host UX корректны.

Вердикт: `NOT_ACCEPTED / PARTIAL_PROGRESS`. Транспорт и большая часть инфраструктуры работают, но memory corpus, discovery, lifecycle, acceptance linkage и диагностическая семантика пока не дают агенту надёжной текущей памяти без ручной forensic-реконструкции.

## 2. Границы и метод

Для Eliot использовались только штатные `mcp__eliot` tools. Raw SQL, прямое чтение SurrealDB и PowerShell-запросы к памяти не использовались.

Источник истины разделён так:

1. exact MCP readback и canonical TaskContract state;
2. текущий source/Git/test audit из предыдущего отчёта;
3. Eliot observations и claims как evidence/history, но не автоматическая truth;
4. сообщения пользователя в текущем чате как evidence процессных ошибок агента, если соответствующей Eliot-записи нет.

Полнота доказана только для claims: task-scoped curation counts по девяти обнаруженным контрактам суммируются ровно в corpus total 54, а exact L2 вернул 54/54 без missing/forbidden.

Для TaskContract, observations, EvidenceAtom, FailureFingerprint и ContextPacket полного list/pagination surface нет. Поэтому перечисление этих типов является максимально полным по доступным MCP surfaces, но не математически исчерпывающим.

### 2.1. Ошибка текущего аудита

Один субагент вызвал `eliot_collective_trace`, ошибочно приняв его за read/status surface. Tool фактически создаёт запись.

- до вызова: revision/sequence `189/189`;
- после вызова: `190/190`;
- trace: `collective:d398ad35-0683-41e3-a8eb-69deb65f7bc0:019fd1be-9afd-7c60-881e-5526ebaead7b`;
- stored observation/receipt: `observation:019fd1be-9afd-7c60-881e-55411f0166e2`;
- содержание: empty collective trace, contributions `0`;
- stored payload сократил `collective_trace_id` до `collective:d398ad35` и сохранил `write_receipt=null`, хотя caller response содержал полный ID/receipt.

Это agent-caused mutation и нарушение заданного read-only подскоупа. Запись не удалялась и не скрывалась. После неё write-like tools не вызывались до запланированной финальной записи результатов аудита.

## 3. Инвентарь

| Тип | Обнаружено | Полнота | Состояние |
|---|---:|---|---|
| ClaimCard | 54 | полная | 54 weak, 54 active, 0 supported, 0 verified |
| TaskContract | 9 | неполная в общем случае | 8 open 0/2, 1 done_verified 2/2 |
| ToolObservation | не менее 37 релевантных | нет list API | audit, host, verifier-like, failure и generated observations |
| VerificationRun | 1 project-linked | нет list API | passed, но scope семантически уже acceptance item |
| EvidenceAtom | 0 surfaced | глобальная полнота не доказана | exact coverage 0 |
| FailureFingerprint | 0 surfaced | глобальная полнота не доказана | failures сохранены преимущественно как ToolObservation |
| ContextPacket | 0 canonical task packets surfaced | глобальная полнота не доказана | есть unverified capsules и generated UL artifacts |
| Incident | 6 | полная для incident list | 5 open, 1 closed; все global/unattributed |
| Distillation corpus | 139 | exact profile | 139 cold, 172,320 bytes, candidates 0 |
| Runtime logs | 100-event bounded sample | неполная | 26 fully redacted errors, project attribution 0/100 |
| External providers | 8 registry entries | полная для registry | 5 enabled mocks, 3 disabled real adapters, Claude/Opus отсутствует |
| Runtime modules | 4 | полная для manifest read | health-only; IDs нестабильны между чтениями |

### 3.1. Claim authorship

Payload profiles:

- `dynamic_agent`: 28;
- `codex_controller`: 13;
- `claude_governed`: 11;
- `codex_worker`: 2.

Несмотря на четыре явных source profiles, `cross_agent_source_diversity=0`. Это либо дефект метрики, либо метрика игнорирует весь candidate-only corpus; в обоих случаях текущий показатель бесполезен для оценки реального cross-host diversity.

Все 54 claims имеют provenance, freshness rule, expected reuse note и 1–3 cue bindings. Ни у одного нет curation disposition.

## 4. TaskContract ledger

| Rev | Status | Task ID | Title | Claims | Canonical evidence |
|---:|---|---|---|---:|---|
| 124 | done_verified 2/2 | `019fc983-0000-7000-8000-000000000010` | ELIOT official host plugin fleet final acceptance 2026-08-03 | 14 | 1 observation, 1 verification, lease/proof |
| 127 | open 0/2 | `2cf15ca6-455f-4831-9124-53b6ffc2c7fd` | Cross-host OpenCode and Antigravity CLI/UI read-write acceptance | 28 | none |
| 125 | open 0/2 | `e570d928-03bb-49d8-bd17-cfa9a033c6dd` | Repair OpenCode global startup and scope | 0 | none |
| 80 | open 0/2 | `03a1a297-ebc1-417f-b29b-88963372eec9` | Read-only memory audit and governed writeback | 5 | none |
| 73 | open 0/2 | `e662181a-2d84-4c1a-9748-1c08d393ddb2` | Runtime Supervision 01 recovery | 3 | none |
| 51 | open 0/2 | `ae60e4a6-6263-4faf-8d31-ae84473acb9f` | CQ-3 interrupted continuity | 1 | none |
| 50 | open 0/2 | `7371434f-250f-43f5-a284-70ab52b4bf4a` | CQ-2 aligned CLI discovery | 1 | none |
| 49 | open 0/2 | `5d0b1dd2-b50c-4da3-90f4-caa6b1bdebf6` | CQ-1 Desktop CLI discovery | 1 | none |
| 47 | open 0/2 | `d398ad35-0683-41e3-a8eb-69deb65f7bc0` | C7-01 cognitive completion candidate | 1 | none |

`host_session_status` показывает только восемь open candidates. Завершённый fleet contract найден через `task_id` четырнадцати claims. Следовательно, прежний вывод «есть восемь контрактов, все открыты» был выводом о discovery surface, а не о полном task corpus.

### 4.1. Скрытый `done_verified` fleet contract

Канонические ссылки:

- observation: `observation:019fcb99-0000-7000-8000-000000000202`;
- verification: `verification:019fcb99-0000-7000-8000-000000000203`;
- ActionLease: `019fcb99-0000-7000-8000-000000000201`;
- completion write: `019fcb99-0000-7000-8000-000000000204`;
- verification scope hash: `f3348b52c4ac52c775eae4f9e23f26e6caac8cf30dbc1e014515f1146d4ae8f7`.

Observation утверждает exact five-host write/readback и OpenCode default project binding. Однако acceptance item `fleet_verification` описан как «All host doctors, hashes, protocol surfaces, Git commit and push pass», а зарегистрированный verifier называется `daemon-receipt-resolution` и его artifact scope содержит только hash одного Eliot write receipt.

То есть verifier доказывает, что daemon разрешил canonical receipt, но не независимо проверяет перечисленные host doctors, binary hashes, protocol surfaces, Git commit и push.

Дополнительные несогласованности:

- observation payload имеет `candidate_only=true`;
- VerificationRun top-level поля `project_id`, `task_id`, `memory_revision` равны `null`, хотя значения есть внутри payload/artifact_scope;
- L2 relations для observation и verification пусты; связь существует только внутри TaskContract;
- `eliot_verifier_status` для этого завершённого task возвращает `-32603: no latest VerifierRun report found`;
- completion proof заявляет `known_risks=[]` и `residual_uncertainty=none`, но уже на revision 125/127 созданы новые repair/acceptance tasks, а позднее зафиксированы Claude/OpenCode/Antigravity дефекты;
- invalidation list не включает смену host binary/plugin/client/config, хотя claims требуют revalidation именно при таких изменениях.

Это `P0 candidate`: acceptance semantics могут позволять `done_verified` при verifier scope, который существенно уже acceptance item. Нужен source-level trace и replay; один live record сам по себе не доказывает универсальный exploit.

## 5. Полный ClaimCard ledger — 54/54

### 5.1. Audit task — 5

| Rev | Handle | Краткий смысл | Disposition candidate |
|---:|---|---|---|
| 186 | `claim:b1e4a2f0-6d3c-4e21-9a5f-7c8d1e2b3a4c` | default recall projection lag rev82 | оставить failure episode; проблема подтверждается сейчас |
| 168 | `claim:d3b07384-9a2c-4f1b-a5d6-7890e1f2a3b4` | «external auditor confirmed» другой weak claim | suppress до независимого verifier evidence |
| 165 | `claim:62ac91f0-ccb3-49b9-b56b-e44a287a2fb8` | C7 source/docs contradiction | сохранить diagnostic hypothesis |
| 85 | `claim:0fb70f96-1d84-46af-a9d5-ec9998b7dfe5` | C7-03C collision blocker | reconcile с current source и exact replay |
| 82 | `claim:84dcbbbb-8839-4fb1-a2d6-c1c9361f10b4` | governed audit procedure | полезный reusable candidate; требует verifier promotion |

### 5.2. Runtime supervision — 3

| Rev | Handle | Краткий смысл |
|---:|---|---|
| 76 | `claim:d4f6b14a-02f7-4d1a-8bb2-3c286ac17d64` | external smoke может оставить TaskRoleLease/AgentSession active |
| 75 | `claim:13b73b74-56ea-43fc-a02c-c147c5de63e7` | S14 legacy-generation recovery boundary |
| 74 | `claim:10ed14b3-8908-4a38-b81d-736b3122fb6b` | default-instance routing и attestation boundary |

### 5.3. CQ/C7 claims вне окна `current_state` — 4

Индивидуальная revision через L2 не возвращается; они старше revision 74.

- `claim:c9351b8b-cf66-47ec-a6e9-53acb8d0a43a` — CQ-1, Desktop CLI cache discovery;
- `claim:d7d34e0c-dc36-492e-9f0e-abb2dcbbcf0d` — CQ-2, два discovery owner и rejected WindowsApps route;
- `claim:b3bb447e-14a2-49f5-860d-1fd225f88092` — CQ-3, interrupted verifier checkpoint;
- `claim:47e8de2d-a8cc-4fc7-9ca7-c1ebe5fb0ee5` — C7-01, Windows credential-test isolation.

### 5.4. Cross-host task — 28

#### Дубли состояния и meta-дубли — 8

- r167 `claim:019fd0fa-0356-7ab1-bc09-a208699c766f` — анализ proliferation того же open-task fact;
- r166 `claim:00000000-0000-7000-8000-000000000003` — open 0/2 snapshot;
- r164 `claim:b82a3f91-5612-4c8d-a419-7d0e8210bc92` — blind read существования предыдущего claim;
- r162 `claim:c246e8b1-9d4a-4f3e-8b7a-52c9d1e6a4f0` — open 0/2 snapshot;
- r161 `claim:94d3c9e2-8f7a-4b5c-9e3f-2a6d8b4c7a9f` — open 0/2 snapshot;
- r155 `claim:a1e99cf4-a66b-408f-8cd8-5bff827c7091` — Claude blind snapshot;
- r154 `claim:73ce52e2-f521-419d-8115-9162fd80e9b0` — Codex blind snapshot;
- r153 `claim:da8a8226-3cf9-4aff-99fe-461a0472435e` — Antigravity blind snapshot.

`a1e99...` и `000...003` прямо требуют считать себя stale после revision 154. `019fd0...` требует revalidation после 180, `b82...` — после 163. На revision 190 все четыре всё ещё `active`, related lifecycle receipts пусты, stale/repetition penalties равны нулю для попавших в rank trace.

#### Полезные технические промежуточные записи — 2

- r143 `claim:7a2f357d-5e2b-4b4d-84a6-050187898237` — packet mandatory floor 4275 > hard ceiling 4096 и bounded trimming repair;
- r140 `claim:e64c832a-b54b-4d2a-a6a2-92ca2ac63a2f` — десять blind sessions, три Opus 4.6 Thinking sessions, interface-precision conclusion; явно interim и уже требует supersession.

#### Smoke/schema/nonce records — 18

- r159 `claim:fa267fd9-ad93-4e3f-87f3-8e1eef3dcde0` — 200-char Unicode candidate schema test;
- r152 `claim:55fcb538-e759-4b4b-a254-0f40218ad5df` — OpenCode UI smoke;
- r151 `claim:ef045b6e-823f-4a26-9b1f-9390b3c72d57` — OpenCode CLI smoke;
- r150 `claim:8b3aa913-3693-48d8-bc78-bbb4feb3d10e` — Antigravity CLI smoke;
- r149 `claim:91808913-9e2d-45d7-885a-8fcc1db11f2b` — Claude Desktop smoke;
- r148 `claim:81182f7f-4948-491a-84f9-6aefea8de957` — Claude Code smoke;
- r147 `claim:7fcf41b4-ff60-4f63-a672-b11fc2626051` — OpenCode host smoke;
- r146 `claim:b3557a4e-ee47-452f-ba33-464c17b4da0b` — Antigravity host smoke;
- r139 `claim:d2bb9f51-39fd-4fa5-b1c8-086e8ff31c04` — OpenCode v3 UI;
- r138 `claim:c9f26d38-30ce-4be4-95d0-4e8f1f75ac5c` — Antigravity v3 UI;
- r137 `claim:7a87a790-8dd5-441a-bc0f-5f2bcfe257bb` — Antigravity v3 CLI;
- r136 `claim:4d67a65b-9c9e-4e18-8d11-041d8888fc31` — OpenCode v3 CLI;
- r135 `claim:51f07476-0c3a-4b11-a196-851d5a2b5a40` — OpenCode final UI cohort;
- r134 `claim:0f84e789-dbf6-4c4e-9c3b-3984e8c6c829` — Antigravity final UI cohort;
- r133 `claim:8127c2f6-07a1-4864-8142-71b2abb4257a` — Antigravity final CLI cohort;
- r132 `claim:9d4fca9e-7c1b-4a52-8c3d-2a1e7f6b9021` — OpenCode final CLI cohort;
- r131 `claim:40b61ff9-3f8f-486b-aeca-0b26a342a59a` — OpenCode exact-generation CLI nonce;
- r130 `claim:6b2a8cf3-77a7-4825-920c-a88c01af8775` — OpenCode exact-generation UI nonce.

Эти records полезны как episodic acceptance receipts, но не как 18 active reusable claims. Их следует переносить в host-run/experience ledger или архивировать из normal recall после reconciliation.

### 5.5. Completed fleet task — 14 исторических host claims

Первый cohort:

- r103 `claim:019fc97d-0000-7000-8000-000000000021` — OpenCode installed;
- r104 `claim:019fc97d-0000-7000-8000-000000000022` — Antigravity installed;
- r105 `claim:019fc97d-0000-7000-8000-000000000023` — Claude Code installed;
- r106 `claim:019fc97d-0000-7000-8000-000000000024` — Claude Desktop installed.

Hash `394D6100126B...` cohort:

- r107 `claim:019fc97d-0000-7000-8000-000000000031` — OpenCode;
- r108 `claim:019fc97d-0000-7000-8000-000000000032` — Antigravity;
- r109 `claim:019fc97d-0000-7000-8000-000000000033` — Claude Code;
- r110 `claim:019fc97d-0000-7000-8000-000000000034` — Claude Desktop;
- r111 `claim:019fc97d-0000-7000-8000-000000000035` — Codex.

Hash `A73E0E94...` cohort:

- r116 `claim:019fcb90-0000-7000-8000-000000000101` — OpenCode;
- r117 `claim:019fcb90-0000-7000-8000-000000000102` — Antigravity;
- r118 `claim:019fcb90-0000-7000-8000-000000000103` — Claude Code;
- r119 `claim:019fcb90-0000-7000-8000-000000000104` — Claude Desktop;
- r120 `claim:019fcb90-0000-7000-8000-000000000105` — Codex.

Поздний final-v11 Governor имеет SHA-256 `5CAE5AF2A400F7DD056E744A41E3835725BD056D2307FEC852C8B39B82B8B2F8`. Следовательно, claims, чья freshness ограничена старым SHA/version, больше не являются current host truth. Они должны остаться audit history, но уйти из active normal recall.

## 6. Важные ToolObservation и Verification records

### 6.1. Аудит, память, правила и timing

- `observation:a4057f1c-09de-4ad2-832e-42bf1643fd7c` — полный проектный аудит, revision 189, verdict `NOT_ACCEPTED_PARTIAL_PROGRESS`;
- `observation:ded98b7f-ae35-48ab-bdd1-16a35b3bb1ff` — базовый read-only memory/Git audit;
- `observation:871ebf9f-806b-422a-afd5-6b0880986da1` — superseding C7 dirty-worktree status;
- `observation:2ede4695-2ee0-410d-9e02-3b8e5a211129` — разделённый latency ledger;
- `observation:34f05491-6e4d-4048-993e-8f16de2e8060` — Git и reusable-failure ledger;
- `observation:d8c7d9e4-31a5-4ec5-a781-9d29400d59d8` — ELIOT skill Meta principle;
- `observation:6d1c3562-0fb2-4558-9ef0-2f4ef3c0bf52` — write/readback pass, acceptance linkage gap;
- `observation:9384e721-b36d-4bb6-99a0-5da868f4cbaf` — два stalled cheap-agent writes без receipt/side effect;
- `observation:f42f2a91-7c4d-41c6-8d79-1ce2bbb860ab` — README/live candidate schema drift;
- `observation:c3e32bf1-e2fc-4d09-9988-e5a1f741cb5d` — audit artifact создан, ignored/uncommitted;
- `observation:ece3864a-d6a6-426a-aed2-df4c5bbaf085` — current-run timing appendix.

### 6.2. Fleet, installer и Code Graph

- `observation:019fcb99-0000-7000-8000-000000000202` — canonical five-host exchange для скрытого done task;
- `verification:019fcb99-0000-7000-8000-000000000203` — daemon receipt-resolution verifier;
- `observation:019fcab5-a123-7abc-8def-0123456789ab` — official host fleet live recheck, task evidence gap;
- `observation:a20632ab-9cda-56b9-a8b6-bae51f983138` — Codex system plugin repair; root causes включают fatal provider-only integrity, `required=true`, incomplete cache identity и broken hook contract;
- `observation:8ac686f0-e97d-4da3-ab88-dbe438fc7ddf` — final-v7 installed, governed action still fail-closed;
- `observation:839a12dd-3e55-53a0-ac93-d0b279f4d6eb` — final-v11 build и graph 25,388 nodes / 122,334 edges;
- `observation:bfe06dd7-a124-58ea-9613-dc75d159cc18` — final-v11 source-current, graph 25,393 / 122,565;
- `observation:b70a4198-a502-5eec-93d6-fd2684564dfd` — final-v11 fleet installed, GitHub issues 7–9, TaskContract open;
- `observation:9310b6ef-2dda-5cae-9b56-75d10e210b3b` — final-v11 pushed with open issues;
- `observation:41223763-2ec9-5c30-baff-850637a56758` — canonical graph namespace stale: 20,462 / 94,109, unique final-v10 namespace used as workaround;
- `observation:e4e1aae4-478b-52d1-a7d5-9b62249ab996` — Antigravity validator passed rules, runtime rejected invalid frontmatter.

Вывод по Code Graph: граф действительно строился и final-v11 unique index содержал актуальные символы. Но canonical namespace остался stale, а текущий `eliot_codecortex_latest` вообще смотрит в data root и возвращает пустой blocked source proof. Это три разных состояния, которые прежние отчёты смешивали.

### 6.3. Host/tool failures

- `observation:6ef199dd-83fe-4c8e-a8a8-3f85cc0cce97` — OpenCode user-reported `missing field project_id`, unbound project context;
- `observation:466490a5-37f1-5f24-87b3-2eb0ec62a8c1` — Claude Desktop `MISSING_PROJECT_PACKET_CONTEXT`; belongs_to relation не восстановила last_task_id, business error превратился в generic `-32603`;
- `observation:ac19475c-7fd0-5b59-a646-6ca6875c4ed5` — Claude final-v9: два fetch_l2 host timeouts, stream не прерывался;
- `observation:4c5a0853-7e2f-516a-bf66-7b4febd1c68e` — Claude UI продолжала «responding», но Eliot tool завершился за 42 ms; доказательств зависшего MCP call не было;
- `observation:563cc5d7-a1b1-46f9-bbe0-46461bd770b5` — Claude Code OAuth expired before API request, 0 tokens;
- `observation:f9e5a1ca-69e0-40e3-a3d4-6448244af29e` — packet hard ceiling exceeded;
- `observation:5cc272bb-aba8-478e-80c7-aa8dc5f648fd` — serialized accounting undershoot: actual ~4627 tokens при отчёте 2446;
- `observation:30e01cbc-e4ac-40a3-8e49-606693b06d98` — broad `git clean` удалил ignored reports tree; восстановлено;
- `observation:019fd1be-9afd-7c60-881e-55411f0166e2` — текущая ошибочная empty collective trace write.

### 6.4. Verification-like observations, не связанные с TaskContract

- `observation:0b6351a6-98da-4b86-97ce-7fed64224c1a` — CLI discovery attempts;
- `observation:60dff384-b9bc-4da0-8c56-9823da800d1b` — self-described DONE_VERIFIED payload при CQ-1 TaskContract open 0/2;
- `observation:c542cb3e-0d86-5b0b-bdf9-5e65cdba2eb0` — focused verifier passed;
- `observation:271b60c9-7dc2-451c-98a1-c19d914d34af` — payload `kind=verification_run`, но record type ToolObservation;
- `observation:b10895c7-507c-49b9-974e-b992bebcc2ca` — Rust compile diagnostic;
- `observation:493a2b86-866f-4f54-b7b4-b259ac7fbce2` — verifier observation;
- `observation:eeed1f1c-0bed-457f-8bfc-eb403a02caaa` — blocked provider/evidence smoke.

Это важная schema/authority проблема: текст внутри observation может говорить DONE_VERIFIED или verification_run, но canonical TaskContract остаётся open и настоящий VerificationRun отсутствует. Агенты должны смотреть на record type и TaskContract linkage, а не на prose payload.

## 7. Recall, output size и ranking

### 7.1. Default projection остаётся stale

На revision 190 обычный `eliot_recall_l0(query="Eliot")` возвращает:

- `projection_revision=82`;
- `projection_state=stale`;
- `memory_confidence=none`;
- `handles=[]`.

Тот же вызов с `lifecycle_audit=true` видит published revision 190. Поэтому claim `b1e4...` не является только историческим эпизодом: default user/agent recall всё ещё воспроизводит проблему. Audit mode скрывает её, а не исправляет.

### 7.2. Response budget

Для 12 возвращённых handles:

- полный structured response: 81,496 chars;
- handles: 2,306 chars;
- rank trace: 78,899 chars;
- collapsed duplicate section: 70,891 chars;
- candidates considered: 907;
- physical canonical corpus: 139;
- duplicate groups: 47;
- collapsed refs: 692.

Крупнейшие generated groups:

- `observation:hotspot-baf52a26973eaf16ed025c1fe1dc77e826fe3ee6e91165b795175e9f6f627116` — 369 refs;
- `observation:co-change-ab2ccfd9b6c55a6d4d6ab8f73f283f47f057cbb7d645e49a0be57375f31319eb` — 123;
- `observation:module-card-003ea150a6a9c9c1a926f61c38072937983e038f63c409571bd5b54553e75d96` — 88;
- `observation:ul-build-45a2646a52c805c72b65bdfdfe9c3b57` — 26;
- `observation:ul-capsule-63994dfc3d3c0b897abced69b0f73e2e` — 22;
- `observation:concept-05c63ea0a564b978939114dfecf72423` — 17.

Это не просто «много данных». Projection материализует сотни derived views и затем возвращает их полный duplicate trace каждому caller. Нужны counts/top-N по умолчанию и отдельный paginated diagnostic handle.

### 7.3. Ranking не использует доступные связи

При exact task ID/concept cues просроченные task claims получили:

- `stale_penalty=0`;
- `repetition_penalty=0`;
- `task_relation=0`;
- `concept_relation=0`;
- `exact_identifier=0`;
- `scope_fit=0`.

Хотя exact L2 показывает `belongs_to` к этому TaskContract. Это объясняет, почему более умная модель не может компенсировать слабый retrieval: нужные relation signals физически есть, но ranker их не использует.

## 8. Lifecycle и curation

На revision 190 curation preview для всех девяти обнаруженных tasks просканировал:

- cross-host: 28;
- completed fleet: 14;
- audit: 5;
- runtime: 3;
- CQ-1/CQ-2/CQ-3/C7: по 1;
- OpenCode repair: 0.

Итого 54. Во всех случаях `candidates=[]` и `total_matching=0`.

Это не означает, что corpus чист. Ручной exact анализ находит:

- восемь claims вокруг одного open-task fact;
- минимум два claims, прямо stale по собственной revision rule;
- ещё два, давно прошедшие mandatory revalidation threshold;
- 14 active host claims, ограниченных устаревшими SHA/version;
- 18 smoke/schema/nonce claims в reusable ClaimCard corpus;
- interim claim `e64c...`, supersession condition которого уже наступила;
- unsupported «external auditor confirmed» claim `d3b...`;
- C7 hypothesis cluster с незакрытым source/docs contradiction.

Distillation одновременно сообщает 139 cold records, `active_bytes=0`, candidates 0. Следовательно, utility/lifecycle engine не выполняет фактическую работу по aging, dedup и memory shaping.

## 9. Глобальные reports, temporal и project leakage

Controller-facing tools без project argument возвращают global `latest`, относящийся не к текущему project:

- `eliot_sleep_report` → project `188b0b87-e50d-84c6-a968-61fb08d05d48`, bundle `sleep-bundle:a8c909e7af9fa5d5792a7418c5d551cbebce20f7974f2895f183290b403e8952`, run `sleep-run:ff381e15395a2397022f98798fd3ce8ee90b0afcd95c147096fda9ceb73cb319`;
- `eliot_verify_inventory` → тот же legacy project, 20 tests;
- `eliot_replay_report` → тот же legacy project; baseline 2025-01-16, candidate 2026-03-22, verdict `pass` от 2026-09-08;
- `eliot_dream_report` → `-32603 latest J0 report not found`.

Текущая дата — 2026-08-05. Future-dated replay verdict и чужой project должны быть исключены из current-project reasoning. Даже если это тестовые fixtures, surface не маркирует их как fixture/foreign в верхнеуровневом ответе.

## 10. Runtime, modules, logs и incidents

### 10.1. Что реально здорово

- daemon runtime ready;
- named-pipe IPC active;
- восемь runtime services healthy;
- четыре health-only modules enabled;
- lockdown inactive.

### 10.2. Что health не доказывает

- module IDs генерируются заново при каждом чтении; две параллельные выборки дали разные UUID для всех четырёх modules;
- CodeCortex `final_status=BLOCKED`, repo root неверен, Git/Cargo adapters failed;
- `git_dirty_adapter` имеет status failed, но summary «working tree clean»;
- ast-grep status pass при `os error 2`;
- diagnostics status pass при `skipped by request`.

### 10.3. Logs

Bounded sample 100 events:

- 26 service health;
- 26 errors;
- 26 daemon starts;
- 22 daemon stops;
- project-bound events: 0/100;
- task-bound: 26/100;
- 26 errors полностью заменены на `[redacted secret-like value]`;
- `fields_ref` отсутствует у всех.

Redaction защищает секреты, но без безопасного error code/fingerprint эти logs непригодны для root-cause analysis.

### 10.4. Incidents

| ID | Status/severity | Смысл |
|---|---|---|
| `incident-019fb23d-7332-74a1-82ac-87b44bce2cd8` | open/degraded | provider call budget exceeded/topology |
| `incident-019fb23d-ab49-7cc2-9ee7-c136eb710ea3` | open/warning | isolated worktree потерял project MCP config |
| `incident-019fb23d-ab69-76f0-bf44-025d330684e4` | open/info | secret scanner false positive |
| `incident-019fb25f-5a13-7fe3-9cb0-78fc669fe800` | open/warning | Claude Desktop Opus turn не hydrated |
| `incident-019fb29c-f9d0-7eb0-9879-f73c26cd02bb` | closed/warning | missing public recovery report root |
| `incident-019fb2d1-a762-70d3-8a42-cdbec0e539ca` | open/warning | provider-plan seal blocked; Claude auth expired |

У всех шести `project_id=null`, `evidence_refs=[]`; open incidents не acknowledged. Они не образуют надёжно attributable project history.

## 11. Проблемы из чата и что о них знает Eliot

| Проблема из чата | Eliot evidence | Вывод и ответственность |
|---|---|---|
| Eliot не был системным/default plugin | `a20632ab`, `019fcab5`, host claims | installer/config defect был исправлен исторически; текущая acceptance всё ещё не закрыта |
| Broken handshake ломал resume и все Codex chats | `a20632ab` фиксирует fatal provider integrity + `required=true` | продуктовая/startup-policy ошибка; user disabling plugin был рациональным recovery |
| Installer должен сам install/update/reinstall | `bfe06dd7`, `b70a4198`, host receipts | dry-run и multi-host plans существуют; self-repair disabled plugin и durable upgrade acceptance доказаны не полностью |
| OpenCode: `missing field project_id` | `6ef199dd`, task `e570d...` | воспроизведён product scope-binding defect; отдельный repair task имеет 0 claims и 0/2 evidence |
| OpenCode агент видел пустой project `eliot` | `6ef199dd`, `019fcb99...202` | historical fix утверждает default binding, но позже понадобился новый task; replay current host generation нужен |
| Claude плохо вызывает tools | `466490a5`, `ac19475c`, `b70a4198` | часть — Eliot task-context/error-mapping bug, часть — host transport/UI desync |
| Claude UI «висит» | `4c5a0853` | tool call завершился за 42 ms; поток был model/UI, а не зависший Eliot MCP call |
| Antigravity plugin validator vs runtime | `e4e1aae4` | validator coverage defect; runtime был прав, validator дал false pass |
| Blind/random tests должны получать факты только из Eliot | `e64c832a` | тесты показали, что интерфейс не раскрывал task/session/fresh state; filesystem fallback не является успехом Eliot |
| Opus умнее Flash, но не должен компенсировать плохой tool | `e64c832a` | Opus лучше отвергал недоказанные claims, но не мог восстановить скрытые факты; interface precision — нижняя граница |
| Eliot выдаёт слишком длинный output | live 81,496-char recall; `7a2f357d`, `5cc272bb` | подтверждён product output/budget defect |
| Code Graph должен делаться | `839a12dd`, `bfe06dd7`, `41223763`; current CodeCortex | graph строился, но namespace freshness и repo binding сломаны |
| Агент полез в PowerShell/raw query вместо MCP | прямой durable record отсутствует; skills/`d8c7d9e4` запрещают bypass | agent process error; должен был быть FailureFingerprint, но его нет |
| Агент прерывал живой/платный Opus stream | chat evidence; поздний corrective `4c5a0853` говорит `left_uninterrupted` | ранняя agent error не записана в Eliot; durable incident отсутствует |
| Агент вводил произвольные timeout windows | chat evidence; `2ede4695` разделяет metric types | agent process error, не доказанный provider hang |
| Два OpenCode окна и filesystem crawling в blind test | chat evidence; прямого Eliot record нет | test-harness/agent design error; результат таких попыток нельзя считать memory acceptance |
| Результаты тестов должны быть в Eliot | десятки claims/observations есть | writeback сделан, но без dedup/lifecycle/acceptance linkage превратился в corpus pollution |
| Все изменения commit/push | `9310b6ef` доказывает final-v11 push; текущий dirty audit branch отдельный | historical release branch pushed; current dirty tree unsafe to commit as a unit |

### 11.1. Дополнительная реконструкция процессных ошибок

История Git/worklog уточняет несколько моментов, которых нет в нормализованном memory corpus:

- утверждение пользователя «handshake ломал resume всех чатов» причинно согласуется с commit, где Eliot был `required=true`, и последующим repair на `required=false`, но exact client logs/session count для слова «все» не сохранены; масштаб следует маркировать `unverified`, а startup defect — доказанным;
- ранний installer использовал 20-секундное окно и дважды завершил корректно принадлежащий daemon, которому реально требовалось около 25 секунд; repair увеличил reconciliation window до 180 секунд и запретил преждевременный kill (`reports/validation/ELIOT_OPENCODE_ANTIGRAVITY_CLI_UI_ACCEPTANCE_20260804.md:302-306`);
- первая Claude Code проверка была испорчена самим harness: случайный `--tools ''` спрятал MCP; такой run правильно не вошёл в acceptance (`...ACCEPTANCE_20260804.md:35-39`);
- blind campaign содержал agent-side ошибки: exact-name filter потратил 116.75 s и запустил 0 tests (`COGNITIVE_COMPLETION_V2_WORKLOG.md:885-890`), был вызван несуществующий `eliot-app --lib`, а OpenCode скопировал static UUID из recovery example и создал `claim:00000000-0000-7000-8000-000000000003`;
- outer envelope оборвался после 904 s, завершил controller, оставил guardian tree и спровоцировал второй concurrent R01; отдельно PF1 был ошибочно оборван shell cap 60 s вместо предусмотренных 600 s (`COGNITIVE_COMPLETION_V2_WORKLOG.md:467-487,748-753`);
- latency ledger хранит Opus consultations 117.4 s, 144.2 s и 917.4 s; позднее около `$5.443919` было потрачено на исправление выдуманных Opus source anchors, а premise 917.4-second консультации затем был опровергнут локальным `float_roundtrip` proof (`COGNITIVE_COMPLETION_V2_WORKLOG.md:1369-1377,1762-1785`);
- эти эпизоды подтверждают претензию пользователя: timeout/interrupt decisions были ошибкой controller/orchestrator, а не доказательством зависшего provider stream. Поздний `observation:4c5a0853-...` фиксирует правильное правило — не прерывать поток, если Eliot уже вернул tool result и host UI продолжает model response.

## 12. Классификация причин

### 12.1. Доказанные/сильные Eliot product defects

1. Default recall projection lag: rev82 против rev190.
2. No pagination/full inventory для claims >50 и остальных record kinds.
3. Rank output 80+ KB для 9–12 handles.
4. Freshness/lifecycle rules не применяются к active claims.
5. Relation/task/exact-cue rank signals остаются нулевыми при exact `belongs_to`.
6. Candidate write/readback не связывается с open TaskContract acceptance.
7. Completed TaskContract скрыт из discovery; verifier status не видит его canonical VerifierRun.
8. Verification field duplication: top-level null, payload populated.
9. CodeCortex project UUID разрешается в Eliot data root, не Git repo.
10. Global report tools возвращают foreign/future data без project fence.
11. Module identity нестабильна между status reads.
12. Incidents/logs не имеют project/evidence attribution.
13. Expected business errors превращаются в generic protocol `-32603`.
14. Curation/distillation не находят очевидные duplicate/stale/historical cohorts.

### 12.2. Host/client defects

- Claude Desktop response/UI state desynchronization;
- Claude host transport timeout после/вокруг Eliot calls;
- Antigravity terminal сохранял старый error после recovery;
- OpenCode managed config/project binding;
- Claude Code OAuth expiry.

### 12.3. Agent/process errors

- premature stream interruption и invented timeout assumptions;
- raw PowerShell/query detour вместо governed MCP;
- blind tests с filesystem fallback;
- повторная запись одного open-task fact вместо dedup-before-write;
- копирование/static use UUID из recovery example;
- трактовка exact readback как acceptance;
- прежнее утверждение «все TaskContracts открыты» без поиска hidden completed contract;
- текущий accidental `eliot_collective_trace` write;
- unsupported external-confirmation claim `d3b...`.

### 12.4. Неизвестно

- где именно зависают cheap-agent writes до dispatch/receipt;
- какое immutable C7 field первым различается;
- первопричина Claude UI hydration/timeout;
- первопричина одного parallel 30-second workspace failure;
- есть ли zero-claim completed TaskContracts, невидимые через текущий surface;
- существуют ли EvidenceAtom/FailureFingerprint вне доступного list surface.

## 13. Candidate-only curation plan

Никакие suppress/supersede/promote действия в этом аудите не применялись.

### P0 candidate

- Replay hidden fleet `done_verified` contract с verifier, который действительно проверяет каждый acceptance clause: host doctors, exact binary/package hashes, protocol surfaces, bidirectional receipts, Git commit/push и invalidation on host generation change.
- Проверить source path, который допускает узкий receipt verifier для широкого acceptance item.

### P1

1. Починить default projection publication и добавить freshness SLO.
2. Применять lifecycle/freshness/dedup до ranking.
3. Вернуть compact rank summary по умолчанию; full trace — только cursor/detail request.
4. Добавить paginated inventories для TaskContract, Observation, EvidenceAtom, FailureFingerprint, ContextPacket и VerificationRun.
5. Свести восемь open-task status claims в один controller-owned result после replay.
6. Архивировать 14 старых fleet claims и 18 smoke/nonce claims из normal recall, сохранив audit history.
7. Привязать OpenCode repair evidence к task `e570...`, а не к соседнему cross-host task.
8. Исправить CodeCortex repo root и canonical graph namespace.
9. Scope global reports по project/runtime generation и отвергать future-dated records.
10. Сделать incidents/logs project/task/evidence attributable.

### P2

- Превратить повторяющиеся error observations в typed FailureFingerprint;
- разделить registration health и behavioral health modules;
- стабилизировать module manifest identity;
- вывести safe non-secret error code рядом с redacted log message;
- перестать хранить test nonce как reusable ClaimCard;
- добавить controller reconciliation queue и dedup-before-write check.

## 14. Что должно появиться в Eliot, но отсутствует

1. FailureFingerprint для broken handshake, stale projection, missing project binding, Claude context failure, long rank output и accidental stream interruption.
2. EvidenceAtom для report hashes, host binary hashes, Git commits, verifier commands и exact UI receipts.
3. VerificationRun, чей scope соответствует каждому acceptance item.
4. ContextPacket/ExposureSet для blind tests, чтобы было видно, что агент действительно получил от Eliot.
5. Typed HostRun/ExperienceCase вместо десятков nonce claims.
6. Supersedes/stale receipts для artifact generations.
7. Incident linkage к project/task/evidence.
8. Canonical CodeCortex report на real Git root и commit.
9. Durable record ранней agent-caused Opus interruption/timeout mistake.
10. One controller reconciliation record, объясняющий, что принято, что отвергнуто и почему.

## 15. Acceptance boundary

Проверено:

- runtime daemon и MCP доступны;
- canonical project identity стабилен;
- exact L2 возвращает все 54 known claims;
- historical host write/readback receipts существуют;
- final-v11 graph и package evidence существуют;
- предыдущий большой audit observation доступен exact readback;
- ошибки retrieval/lifecycle/output воспроизводятся live.

Не проверено/не принято:

- реальная current-generation five-host acceptance replay;
- TaskContract closure для восьми open tasks;
- evidence/verifier promotion корпуса;
- default recall freshness;
- automatic curation;
- canonical CodeCortex repo binding;
- current dirty product tree как единый release;
- real governed Claude Opus provider path.

Этот документ является forensic evidence и curation proposal, а не truth promotion, task completion или permission на автоматическое изменение памяти.

candidate_only; requires reconciliation/replay before activation
