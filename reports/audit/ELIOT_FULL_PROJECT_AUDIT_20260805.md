# ELIOT Memory OS — полный аудит проекта

Дата среза: 2026-08-05  
Репозиторий: C:\Users\kleym\OneDrive\Documents\Rust\projects\eliot-memory-os  
Внешний комплект документации: C:\Users\kleym\OneDrive\Documents\Rust\docs\ELIOT Arhitecture  
Режим: read-only аудит product source; создан только этот отчёт и отдельный индекс CodeCortex.  

## 1. Итоговый вердикт

ELIOT уже не является макетом. Построена большая работающая Windows/Rust-система:

- пять crate с осмысленным разделением типов, canonical store, engine, app и IPC;
- native Governor daemon и authenticated named-pipe IPC;
- canonical write envelope, WriterActor, WAL, receipts и projection outbox;
- управляемые интеграции Codex, OpenCode, Antigravity, Claude Code и Claude Desktop;
- governed memory read/write surface, task contracts, leases, verification, replay, incidents, backup/restore;
- значительная часть Understanding Layer, cognitive projections, context compilation и host/provider supervision;
- большой набор unit, integration, contract и adversarial tests.

Но проект в целом **не завершён и не принят как production-complete**.

Причина не одна. Одновременно существуют четыре несовпадающих состояния:

1. origin/main на commit bccb334 — заявлен как canonical, но не содержит final-v11;
2. текущий committed HEAD b4ec015 — на 17 commit позади final-v11;
3. текущий dirty worktree — 74 изменённых файла, +12855/-8093, смешивает cognitive work, rollback и stale docs;
4. опубликованный/установленный final-v11 a322970 — лучший host/plugin integration head, но не в main, содержит P0 completion bypass и не проходит полный test suite.

Главный системный вывод: ELIOT удалось построить как работающую инфраструктуру, но не удалось удержать **одну каноническую, воспроизводимую и доказуемо принятую версию продукта**.

### Краткая оценка

| Область | Вердикт |
|---|---|
| Архитектурная основа | Сильная, в значительной части реализована |
| Canonical memory/write path | Реализован существенно, но есть P1 integrity gaps |
| Completion truth | P0: публичный legacy fallback допускает ложный DONE_VERIFIED |
| Understanding/cognitive roadmap | Частично; Phase 2 не принят, current dirty содержит rollback |
| Multi-host plugin fleet | Реально работает, но source provenance разорван |
| Тесты current dirty | quick PASS; clippy FAIL; workspace tests FAIL |
| Тесты final-v11 | quick PASS; clippy PASS; full suite FAIL на двух stale fixtures |
| Документация | Смешаны target, historical, status и stale snapshot |
| Eliot memory corpus | Transport healthy; 0 supported и 0 verified claims |
| Release readiness | NOT_ACCEPTED |
| Текущий dirty tree | UNSAFE_TO_COMMIT_AS_A_UNIT |

## 2. Область и метод аудита

Проверялись:

- все пять Cargo crate;
- workspace dependency graph и boundary calls;
- текущий dirty worktree, committed HEAD, main и final-v11;
- maintained repo docs, внешний ELIOT Arhitecture snapshot, worklogs, status и capability matrix;
- Justfile и GitHub Actions gate;
- live Eliot runtime, corpus, incidents, projection, exact L2 и CodeCortex;
- host/plugin state для Codex, OpenCode, Antigravity и Claude surfaces;
- предыдущие audit reports и governed observations;
- targeted и workspace Rust checks.

Иерархия истины:

1. текущие source/Cargo/lock/tests и фактический Git commit;
2. clean branch source и воспроизводимый verifier;
3. installed binary/package с exact hash и receipt;
4. maintained implementation docs;
5. Code Graph, Eliot memory, reports и внешние reviewer outputs как evidence, но не truth.

Аудит не исправлял product code, не переключал dirty checkout и не создавал GitHub issues.

## 3. Карта четырёх состояний

### 3.1 main

- Commit: bccb334021749854df1c10733d0e2fadd4b704ca
- Отстаёт от final-v11 примерно на 94 commit.
- Документ final-v11 называет main canonical branch, но опубликованная реализация туда не интегрирована.
- main не является источником реально установленного fleet.

### 3.2 Текущий committed HEAD

- Branch: codex/cognitive-completion-v2
- Commit: b4ec01513c7ef7694e91a16dfcf7998bef7c9cba
- Является предком final-v11; divergence cognitive...repair = 0 / 17.
- Содержит checkpoint cognitive work, который не был принят.
- Не включает все host/plugin repairs final-v11.

### 3.3 Текущий dirty worktree

- 74 tracked status entries;
- +12855 / -8093;
- untracked .eliot/ с historical inbox/consultation artifacts;
- удалены UnderstandingRuntime, два UL runtime test target и pending-injection SurQL;
- три maintained architecture-файла заменены byte-identical копиями stale external snapshot;
- одновременно присутствуют более новые cognitive primitives и старые/откаченные tests/docs.
- 34 modified files побайтно совпадают со старыми достижимыми Git blobs;
- все шесть deleted files были добавлены одним checkpoint commit b93a937.

Это не coherent patch и не осмысленный revert. Коммитить его целиком нельзя.

### 3.4 Published final-v11

- Branch: codex/all-host-plugin-repair
- Commit: a32297048c89862097a3a40d7c3f8127667b80fd
- Remote branch опубликован.
- Фактический source/artifact commit — f3191d0; a322970 меняет только
  validation report (+50/-2).
- На нём основаны текущие managed host artifacts.
- Исправляет H6 exact-L2 file relation и stale delegation assertion.
- Проходит quick и strict clippy.
- Не проходит полный workspace suite: два positive Antigravity fixture устарели после rule-frontmatter hardening.
- Сохраняет публичный legacy completion fallback и generic completion/cognitive schemas.
- Не является GitHub Release: tags/releases и check runs отсутствуют; commits
  unsigned, Windows executable Authenticode NotSigned.

## 4. Что действительно получилось

### 4.1 Правильное crate-разделение

Workspace содержит:

- eliot-types — чистые контракты и IDs;
- eliot-store — Surreal transport, canonical queries, Blob CAS, WAL-facing store;
- eliot-engine — policy, writer, verification, memory/cognitive services;
- eliot-app — CLI, daemon, MCP, installers, host integrations;
- eliot-windows-ipc — Windows credentials, pipe/security primitives.

Cargo metadata подтверждает пять packages. Основной dependency direction в целом разумный: app оркестрирует engine/store/types/IPC; engine использует store/types; store использует types.

### 4.2 Native Windows hot path

- Rust/MSVC, без Python/Node service в Governor hot path;
- собственный WebSocket/RPC transport к SurrealDB, без SurrealDB Rust SDK;
- Windows Credential Manager и named pipes;
- Justfile как стабильный command surface.

### 4.3 Canonical write architecture

Реализованы:

- WriterActor как нормальный owner записи;
- per-project FIFO внутри процесса;
- write_id idempotency receipt;
- atomic canonical transaction;
- cognitive projection outbox;
- Blob CAS с digest verification и atomic staging;
- candidate-only внешние/агентские записи;
- reversible lifecycle и отдельная verification model.

### 4.4 Host/runtime hardening

Качественно реализованы:

- cooperative daemon rollover без kill-on-timeout;
- повторная проверка publication/lock/pid/process image;
- bounded IPC frame и replay window;
- private profile attestation по generation/token/executable SHA;
- fail-closed Claude family doctor;
- OpenCode installed-state hash/manifest checks;
- Antigravity GUI+CLI MCP and official-plugin checks;
- content-addressed Codex plugin materialization.

### 4.5 Сильные механизмы engine

Существенно реализованы:

- canonical task-aware CompletionGate path;
- writer/admission/read services;
- action/work/worktree leases;
- replay, incidents, backup/restore, export/import, GC;
- host authority generation/epoch/revoke;
- provider journaling и unknown-outcome no-redispatch;
- candidate-only skill/experience/sleep primitives;
- deterministic evaluation framework;
- cognitive projection coordinator для нескольких families;
- context packet compiler primitives.

### 4.6 Реальный multi-host fleet

На момент аудита:

- Codex: ровно один enabled Eliot MCP/plugin; cached Governor SHA совпадает с final-v11;
- OpenCode: native MCP connected, installed-state doctor current;
- Antigravity: GUI+CLI configs и official plugin current; CLI import count 1;
- Claude Desktop: active/current selected surface;
- Claude Code: installed/current, но inactive из-за exact-one-family policy.

Это реальная работающая интеграция, а не только source scaffolding.

## 5. Что не получилось или осталось частичным

### 5.1 Нет одной принятой версии

Самая дорогая незавершённость — не отдельная функция, а release governance:

- main, current HEAD, dirty worktree, final-v11 и installed artifact расходятся;
- graph namespaces отражают разные состояния;
- docs/status не привязаны к commit;
- предыдущие closeout statements описывали fleet как current, но TaskContract оставался open 0/2;
- full clean suite не был доказан.

### 5.2 Completion truth остаётся небезопасной

Канонический task-bound path достаточно строг, но публичный MCP оставляет compatibility fallback:

- crates/eliot-app/src/mcp_stdio/dispatch.rs:1006-1017 принимает CognitiveGateRequest клиента;
- dispatch.rs:1019-1037 при отсутствии write_id/expected_revision напрямую десериализует CompletionProof;
- crates/eliot-engine/src/context.rs:2624-2673 legacy decide проверяет клиентские строки/status;
- crates/eliot-app/src/mcp_stdio/catalog.rs:1351-1361 публикует generic object schemas;
- ignored integration test в mcp_protocol.rs:8257-8293 доказывает, что self-declared payload получает DONE_VERIFIED.

Этот путь присутствует и в final-v11 a322970.

### 5.3 Cognitive/Understanding roadmap не завершён

- C7-03C worklog заканчивается BLOCKED, не certified;
- one engine-owned UnderstandingRuntime отсутствует в current dirty;
- app-owned UlRuntime остаётся constructible;
- pending state process-local и теряется при restart;
- hot path делает DB/full-graph reads и synchronous activation write;
- 500-edge gate сохраняется;
- utility projection объявлена, но unavailable;
- Phase 2 в invariants остаётся LOCKED;
- provider cognition до требуемой фазы запрещена.

### 5.4 Canonical integrity gaps

Статически подтверждены риски:

- writer sequence восстанавливается из redb, но не из canonical scope_head;
- apply_write_envelope без monotonic CAS может откатить project revision после потери WAL;
- global record IDs UPSERT-ятся без проверки прежнего project owner;
- schema migration не имеет version/checksum ledger, lease, backup gate и canonical receipt;
- dirty observability path утратил часть envelope/session identity checks.

WAL-loss и hostile cross-project collision в live DB в этом аудите не воспроизводились, поэтому это P1 static-confirmed risk, а не заявленный incident.

### 5.5 Read consistency неодинакова

- ReadService polling: 25 ms до 5 s;
- current_state и L2 возвращают StaleRead;
- recall_l0 после того же deadline может вернуть Ok с stale/blocked projection;
- обещанного ScopeHeadCache notification нет.

Одинаковый at_least_revision поэтому имеет разную строгость на разных read surfaces.

### 5.6 Verification/eval naming вводит в заблуждение

Канонический task verifier реально запускает зарегистрированные verifiers. Но отдельный VerificationRunnerService создаёт Passed records для известных команд без их исполнения и может дать Allow governance-report. Это не прямой completion bypass, однако имя и output позволяют агенту перепутать planned/synthetic evidence с executed evidence.

ALE/Provider/Future eval families остаются NotYetImplemented или placeholder.

## 6. Crate-by-crate аудит

### 6.1 eliot-types

Сильные стороны:

- UUIDv7 typed IDs;
- strict revision/sequence newtypes;
- typed memory/write/read/observability/UL contracts;
- чистая crate без Tokio, FS и network;
- TaskContract structured acceptance model.

Проблемы:

- JsonSchema и deny_unknown_fields применены не ко всему public ingress;
- MCP TaskContract input дублируется в app;
- catalog описывает acceptance_items только как array без item schema;
- IdempotencyOptions.allow_replay объявлено, но production semantics не реализованы;
- dirty source удалил durable pending-injection batch contract.

Вердикт: PARTIAL_PROGRESS.

### 6.2 eliot-store

Сильные стороны:

- custom Surreal WebSocket/RPC;
- atomic write transaction;
- idempotency receipt и projection outbox;
- Blob CAS;
- FTS candidate admission и deterministic Rust ranking;
- exact L2 с project filtering/continuation.

Проблемы:

- нет canonical sequence recovery и monotonic CAS;
- same record ID может перепривязать record к другому project;
- production migration runner не использует checksummed ledger;
- observability scope/hash/schema validation неполна;
- legacy pending_injection rows могут остаться вне cleanup/secret scan;
- writer status recent receipts/counters не полностью фактические;
- старые 64 KiB/200-atom promises не соответствуют текущим лимитам.

Вердикт: PARTIAL_PROGRESS / production integrity not accepted.

### 6.3 eliot-engine

Сильные стороны:

- WriterActor/admission/canonical task gate;
- host authority и provider supervision;
- safety/backup/restore;
- replay/sleep/candidate mechanisms;
- cognitive projection/context primitives;
- обширные contract/adversarial tests.

Проблемы:

- legacy CompletionGate P0;
- strict L0 consistency violation;
- no ScopeHeadCache notification;
- WorkLease epoch всегда 0, WorktreeLease без epoch;
- provider process checkpoints не связаны с role lease;
- UnderstandingRuntime rollback/missing;
- hot UL invariants не выполнены;
- utility projection missing;
- synthetic verification report;
- oversized modules и dispatcher coupling;
- часть live-Surreal tests ignored.

Вердикт: сильный pre-alpha engine, но NOT_ACCEPTED.

### 6.4 eliot-app

Сильные стороны:

- daemon/CLI/MCP orchestration;
- profile-aware governed tool catalogs;
- recoverable in-band errors;
- managed installers и host doctors;
- content-addressed plugin lifecycle;
- bounded worker outputs.

Проблемы:

- P0 completion/cognitive fallback;
- handwritten generic schemas;
- controller и fetch_l2 output не имеют единого малого ceiling;
- Codex doctor способен ready=true при installed_state=null;
- OpenCode automatic project key использует basename origin и допускает collision;
- OpenCode passive hook child без timeout и наследует весь environment;
- OpenCode install/uninstall не имеют общей transaction/CAS/rollback;
- Antigravity project_root API валидирует, но не связывает проект;
- 71 provisioned MCP tests не входят в just verify.

Вердикт: multi-host runtime работает, но control/release contracts partial.

### 6.5 eliot-windows-ipc

Сильные стороны:

- Credential Manager boundary;
- exact current-user named-pipe DACL;
- generation/token/replay/process attestation;
- bounded frames.

Hardening gaps:

- runtime directory icacls проверяется только по exit code, без инвентаризации explicit ACE;
- secret byte buffers не zeroized на всей цепочке.

Вердикт: наиболее зрелый низкоуровневый слой; P2/P3 hardening остаётся.

## 7. Severity findings

### P0

#### P0-1. Публичный legacy completion path может вернуть ложный DONE_VERIFIED

Статус: подтверждено source + existing test, присутствует в current и final-v11.

Воздействие:

- внешний агент может получить статус, визуально неотличимый от canonical completion;
- нет persisted TaskContract transition;
- нет binding к current verifier run/review/coordination;
- report latest.json создаёт ложное completion evidence.

Требуемое исправление:

- удалить public compatibility fallback;
- либо сделать его status-only legacy assessment, который никогда не возвращает DONE_VERIFIED;
- public completion должен требовать canonical task_id, expected_revision, write_id и server-loaded evidence;
- добавить adversarial active MCP test.

### P1

#### P1-1. Разорван canonical source/release provenance

main, current HEAD, dirty worktree и installed final-v11 различаются. Это уже породило current FAIL на H6, исправленный в final-v11, и stale tests/docs.

#### P1-2. Dirty worktree нельзя коммитить как единый change

В нём смешаны:

- stale snapshot overwrite;
- rollback UnderstandingRuntime/pending injection;
- cognitive projection/context work;
- host/plugin lineage;
- tests разных поколений.

#### P1-3. Возможен rollback canonical project sequence

redb-only sequence allocation плюс unconditional scope_head UPSERT без CAS.

#### P1-4. Возможна cross-project mutation при повторном record ID

Canonical UPSERT не сверяет existing project owner.

#### P1-5. Migration governance не реализован

Embedded scripts переисполняются без version/checksum/lease/backup/receipt.

#### P1-6. Strict recall consistency fail-open

recall_l0 возвращает Ok после missed at_least_revision deadline.

#### P1-7. UL runtime не соответствует собственным locked invariants

Нет one daemon runtime, memory-only hot path, restart-safe pending snapshot и accepted Phase 2.

#### P1-8. Work/provider authority fencing incomplete

WorkLease epoch не монотонен; WorktreeLease epoch отсутствует; provider child не связан с role lease.

#### P1-9. TaskContract MCP schema не single-source

Runtime требует два structured objects; live/catalog surface не описывает item fields и в некоторых clients отображается как string array.

#### P1-10. final-v11 full suite красный

После rule-frontmatter hardening два positive test fixture остались без YAML frontmatter:

- commands/antigravity.rs:1767-1779;
- mcp_stdio/protocol_tests.rs:1181-1184.

Runtime validator правильно fail-closed; defect находится в release test contract.

#### P1-11. CI не эквивалентен final gate

CI запускает fmt/check/test, но не strict clippy. Обычный cargo test не запускает 71 ignored provisioned MCP tests.

#### P1-12. Codex doctor ложноположителен

installed_state=None трактуется как source/current success.

#### P1-13. OpenCode identity/lifecycle/install contracts неполны

Basename collision, unbounded hook child, full environment inheritance и отсутствие install transaction/CAS.

#### P1-14. Controller/L2 outputs могут быть чрезмерными

Worker current_state bounded, codex_controller не входит в тот же set; fetch_l2 и rank/duplicate traces способны вернуть десятки тысяч символов.

#### P1-15. Observability identity validation регрессировала в dirty path

Outer envelope и inner receipt/session/task/hash/schema не сверяются полностью.

### P2

- Antigravity project-aware API фактически unbound;
- Claude surface transition disable-then-enable без rollback;
- provisioned live tests отделены от стандартного gate;
- legacy pending_injection не имеет upgrade cleanup;
- L2 byte/atom contract не закреплён актуальным ADR;
- writer report содержит не полностью реальные latest/counter semantics;
- schema registry хранит имена schemas, но не валидирует все payloads;
- synthetic verification report не отделён достаточно явно от executed proof;
- fixed test ports и тяжёлые self-rerun fixtures ухудшают feedback loop;
- giant dispatch/installer/engine modules имеют высокий blast radius;
- CodeCortex default/latest может быть stale или относиться к неправильному root.

### P3

- secret buffers zeroization неполна;
- runtime directory ACL postcondition не доказан;
- allow_replay contract field не используется;
- фактический BlobStore format расходится со старыми zstd/inline promises;
- retryability taxonomy StoreError не единообразна;
- status docs не generated/commit-bound.

## 8. Тесты и диагностика

### 8.1 Current dirty worktree

| Проверка | Результат |
|---|---|
| cargo metadata | PASS |
| cargo fmt --check | PASS |
| cargo check --workspace --all-targets | PASS |
| just quick | PASS, около 12.5 s |
| strict clippy | FAIL, 85.7 s |
| just test | FAIL, 241.7 s |
| exact H6 repeat | FAIL, 28.2 s |

Clippy:

- eliot-types/src/ul/cue.rs:466 — expect_used;
- eliot-types/src/ul/cue.rs:526 — expect_used.

Workspace test:

- eliot-app/tests/ul_behavior_cli.rs:247;
- h6_co_change_is_reachable_from_canonical_file_handle;
- canonical co-change relation missing: [].

Root cause:

- current canonical_store.rs:561-569 пропускает L2HandleKind::File;
- exact-L2 физически не запрашивает file co_change endpoint;
- исправление есть в final-v11 commit b44ae96.

Дополнительный current failure:

- delegation_policy expected legacy .run_real text;
- production уже вызывает .run_real_recorded_supervised;
- assertion исправлен в final-v11.

Focused crate checks агентов:

- eliot-types/store: cargo check all targets PASS; 36 targeted tests PASS,
  diff-check PASS;
- eliot-engine: три bounded groups дали 97 passed/6 ignored,
  179 passed/1 ignored и 155 passed/1 ignored/1 stale-test failed;
- worktree lease focused suite: 34/34 PASS, но около 103 s;
- ul_cue_firing использует fixed ports 8901/8902; один порт был занят внешним
  процессом, поэтому это harness/environment blocker, не доказанный UL defect.

### 8.2 Clean final-v11 clone

Точный commit: a322970.

| Проверка | Результат |
|---|---|
| clean checkout status | PASS, 0 entries |
| just quick | PASS, 119.6 s |
| strict clippy | PASS, 91.2 s |
| exact H6 | PASS 1/1, 21.14 s |
| just test | FAIL, 212.4 s |

Основной binary suite:

- 308 passed;
- 2 failed;
- 2 ignored.

Оба failure имеют один root cause: stale positive Antigravity fixtures после frontmatter validation. Реальный official rule имеет valid frontmatter; production validator работает правильно.

Следовательно, final-v11 лучше current dirty, но full-suite green claim неверен.

### 8.3 Ignored/live coverage

- mcp_protocol.rs содержит 71 ignored test;
- additional ignored live-Surreal/restart tests есть в engine/store;
- стандартный just verify их не запускает;
- отдельный scripts/run-isolated-tests.ps1 умеет McpOnly/RunIgnored, но не включён в release gate.

### 8.4 LSP/Code Graph

Cargo является рабочим source of truth.

Rust LSP MCP в этом сеансе вернул dispatch.rs как unlinked file и не нашёл workspace symbols, поэтому semantic LSP proof отсутствует. Это tool/workspace configuration gap, не Rust diagnostic.

Создан отдельный read-only graph exact current worktree:

- eliot-memory-os-audit-20260805-current-worktree;
- 25,200 nodes;
- 118,203 edges;
- 467 indexed files.

Existing final-v11 graph:

- 25,393 nodes;
- 122,565 edges.

Графы использованы только для routing/hotspots; все критические claims подтверждены source/tests.

### 8.5 Remote CI/release

Remote проверен 2026-08-05:

- open PR: 0;
- tags/releases: 0;
- check runs/statuses для b4ec015, f3191d0 и a322970: 0;
- единственный workflow срабатывает только на push/pull_request к main;
- последний green run 30322498639 относится к main@bccb334 от 2026-07-28;
- CI не запускает strict clippy, provisioned ignored MCP, operator-check,
  package/security verifier, artifact upload или release job;
- branch protection/rulesets нельзя подтвердить: GitHub API возвращает 403
  для private repository plan.

Локальные artifacts совпадают с historical report:

- eliot-governor.exe: 60,997,632 bytes,
  SHA-256 5CAE5AF2A400F7DD056E744A41E3835725BD056D2307FEC852C8B39B82B8B2F8;
- eliot-0.1.25-windows-x64.mcpb: 18,569,574 bytes,
  SHA-256 D95F311D63107D4918A6AFBEFE26E797645992392C7CA82E8498CD7577AB5576.

Однако нет independent signed binary-to-commit provenance: RELEASE.json,
SHA256SUMS.json, GitHub artifact/release/tag/attestation отсутствуют.

## 9. Документационный аудит

### 9.1 Внешний каталог не является source

Его README прямо говорит:

- Snapshot — not the source;
- документы не maintained;
- maintained versions должны жить в repo docs/architecture;
- изменения нужно переносить в canonical docs, а не редактировать snapshot.

### 9.2 Dirty repo docs ошибочно равны snapshot

Три файла в current dirty repo byte-for-byte равны внешним stale copies:

- ELIOT_Canonical_Master.md;
- ELIOT_Rust_Governor_Production_Architecture_v1_0.md;
- ELIOT_Understanding_Layer_Engineering_Task_v1_4.md.

Это подтверждённый process/agent error: snapshot был возвращён в maintained location.

### 9.3 Status contradictions

- UNDERSTANDING_LAYER_STATUS.md: Status certified и все PASS;
- COGNITIVE_RUNTIME_INVARIANTS.md: Phase 1 active, Phase 2 LOCKED;
- COGNITIVE_COMPLETION_V2_WORKLOG.md: C7-03C BLOCKED, no fourth rerun;
- dirty capability matrix говорит coordinator absent, хотя symbol существует;
- final-v11 matrix всё ещё не принимает Phase 2.

Слово certified относится максимум к historical bounded run, не к текущему продукту.

### 9.4 Ошибочные технические claims

Stale snapshot возвращает:

- четыре crate вместо пяти;
- SurrealDB Rust SDK вместо custom WebSocket/RPC;
- старые pending-injection и token-budget assumptions;
- target architecture как будто она current implementation.

### 9.5 Нужная модель документации

Каждый крупный claim должен иметь один из статусов:

- TARGET;
- IMPLEMENTED_UNVERIFIED;
- VERIFIED_COMPONENT;
- ACCEPTED_PRODUCT;
- HISTORICAL;
- REJECTED/SUPERSEDED.

Status/capability manifest должен быть commit-bound и генерировать краткие status pages.

### 9.6 Доказанная история normalization и rollback

Правильная normalization уже была сделана:

- 5ef12fc — добавил vision/implementation disclaimer и исправил SDK/crate claims;
- a80f0fe — заменил dated UL audit snapshot на prerequisites;
- 7184d48 — отделил compact current implementation от future design,
  удалив около 8,160 устаревших строк.

Dirty tree вернул exact старые blobs:

- capability matrix — blob 97e8420;
- Canonical Master и UL task — root-era blob b5c84d4;
- current architecture 221 lines заменена старой design/task версией
  примерно на 5,789 lines.

Committed b4ec015 фиксировал C7-03C/Phase 1 PASS и C7-04A как
CHECKPOINT — NOT ACCEPTED с тремя blockers. Dirty worklog переписал этот участок
другой C7-03C lineage и завершил его U9.6 collision/BLOCKED. Такое допустимо
только как explicit rollback/rework с provenance manifest, которого нет.

### 9.7 Stale status/ADR/evidence lifecycle

- UL_PROGRESS и UNDERSTANDING_LAYER_STATUS не имеют exact SHA,
  superseded_by и validity boundary;
- historical UL v1.4 component certification на main выглядит как current
  product certification;
- ADR 0001 сохраняет четыре crate и не имеет Status/Date/Superseded;
- ADR 0003 и ARCHITECTURE_CONTRACT/AGENT_HOST_INTEGRATIONS используют
  stale FinishGate, хотя current invariant разрешает только CompletionGate;
- ADR 0004–0009 не имеют единого Applies-to SHA/Supersedes lifecycle;
- .gitignore игнорирует reports/, поэтому большинство audit/blocked artifacts
  отсутствуют в fresh clone;
- final-v11 validation report одновременно говорит installed/open issues и в
  footer оставляет report force-add/final commit/push как PENDING.

Evidence без tracked disposition и supersession снова становится локальным
контекстом, а не воспроизводимой историей проекта.

## 10. Eliot memory/runtime аудит

### 10.1 Что работает

- runtime health healthy/ready;
- readiness report ready;
- exact project identity eliot-memory-os:
  87731db9-1e51-8fde-a4db-222705d7d03a;
- canonical memory revision/project sequence: 188/188;
- exact L2 readback полного audit bundle: 11/11, missing 0, forbidden 0;
- module registry отвечает;
- incident service и lockdown state доступны;
- записи и receipts реально сохраняются.

### 10.2 Что не работает как knowledge system

Corpus profile:

- claim_cards: 54;
- supported: 0;
- verified: 0;
- weak: 54;
- active: 54, stale/superseded/deleted: 0;
- exact_evidence_coverage: 0;
- verifier_link_coverage: 0;
- weak_claim_fraction: 1.0;
- validated procedures/cases/patterns/transfers: 0.

Это означает: Eliot сегодня хранит много полезной истории и candidate evidence, но почти не имеет governed knowledge, которое можно безопасно считать подтверждённым.

На stored baseline rev 87 было 9 weak claims. На rev 188 их 54:
+45 claims и +101 revision без promotion хотя бы одной записи.

Distillation preview: 139 records, 172,320 bytes, все cold,
active_bytes=0, candidates=0.

### 10.3 Task/acceptance debt

Найдено восемь TaskContract. Все:

- open;
- acceptance 0/2;
- observation_ids пусты;
- verification_ids/scopes пусты;
- completion/understanding proofs отсутствуют;
- action lease отсутствует.

Task revisions: 47, 49, 50, 51, 73, 80, 125, 127.
Наиболее свежий cross-host TaskContract
2cf15ca6-455f-4831-9124-53b6ffc2c7fd отстаёт от current state на 61 revision.

Verifier status трёх свежих tasks возвращает MCP error no latest VerifierRun,
а не typed not_found. Транспортный read/write и installed fleet не равны
завершённому TaskContract.

Historical audit bundle exact-fetches 11/11 на fence 188, но содержит
evidence_atoms=[] и verification_runs=[]; видны только две relations
claim -> belongs_to -> TaskContract. Это transport proof, не acceptance.

### 10.4 Incidents

Incident list содержит шесть записей: пять open, одна closed. Lockdown inactive.

Open classes включают:

- provider call budget exceeded;
- invalid config/project governor discovery;
- secret scanner false positive;
- Claude Desktop response hydration/desync;
- legacy schema/policy mismatch, блокирующий provider-plan seal.

Healthy doctor не означает отсутствие operational debt.

У всех incidents project_id=null и evidence_refs=[]; open incidents не
acknowledged. Поэтому их нельзя надёжно атрибутировать этому project, хотя
affected surfaces включают action_lease, patch_runner и completion_gate.

Четыре built-in module health entries имеют новый module_id на каждом read.
Если ID предназначен для корреляции, это отдельный stability defect.

### 10.5 Projection/output проблемы

- normal recall_l0: projection_state stale, revision 82, handles пусты;
- canonical state: revision 188; lag default recall = 106 revisions;
- lifecycle_audit=true видит published projection revision 188;
- limit=10 diagnostic response: 83,980 символов;
- rank trace: 76,787 символов;
- collapsed-duplicate trace: 70,891 символ;
- 47 duplicate groups и 692 collapsed refs;
- current_state limit=50: 22,451 символ, truncated=true, без pagination,
  поэтому 4 из 54 claims недоступны через этот surface.

У одного cross-host task curation видит 28 active claims, но предлагает ноль
suppress/promote/archive candidates. Семь отдельных claims повторяют один факт
open/pending 2/2. Три уже нарушили собственные freshness rules, однако остаются
active и получают stale_penalty=0/repetition_penalty=0.

Даже точные concept/task cues получают нулевые concept_relation,
exact_identifier, scope_fit и task_relation signals.

Native eliot_codecortex_latest в этом сеансе указывал на
C:\Users\kleym\AppData\Local\Eliot, а не на repo:

- final_status BLOCKED;
- git_head/branch unavailable;
- crates/files/symbols/targets пусты;
- Git/Cargo adapters failed;
- diagnostics skipped;
- memory_receipt null;
- ast-grep entries pass при os error 2;
- git adapter failed при summary working tree clean.

Это не CodeUnderstandingProof репозитория.

### 10.6 External review

Governed provider registry в этом сеансе содержит только mock providers.
Реального Claude/Opus provider через Eliot нет. Поэтому независимый Opus review
не выполнялся и mock output не выдавался за аудит.

## 11. Host integrations

### Codex

Фактическая установка current. Но doctor contract слаб: installed_state=null
может дать ready=true. Требуется проверять ownership manifest, exact one
registration, enabled state, cached version/SHA и running parity.

### OpenCode

Фактический MCP connected. Остатки:

- collision-prone automatic project key;
- passive hooks без deadline;
- child наследует весь environment;
- installer без общей transaction/CAS/rollback.

### Antigravity

GUI/CLI registration и official plugin current. Но:

- project-aware method не создаёт project authority;
- runtime smoke не является частью doctor;
- два release tests имеют stale fixtures;
- historical terminal error after recovery остаётся issue.

### Claude Code/Desktop

Installed family current, активна ровно одна surface. Доказательства прежнего
write/readback полезны, но fresh final-v11 paid-model E2E в этом аудите не
выполнялся. Desktop UI/response desync остаётся unresolved.

## 12. Что было ошибкой агента/процесса, а что неизвестностью

### Подтверждённые ошибки агента/процесса

1. Stale external snapshot скопирован обратно в maintained docs.
2. Final fixes оставлены в repair branch и не интегрированы в main/current work.
3. Targeted green tests и host hashes были описаны слишком близко к product completion.
4. TaskContract 0/2 не был reconciled, хотя closeout звучал как завершение.
5. Code Graph/status matrix использовались без обязательной commit/source проверки.
6. C7-04A review slice был слишком большим; cross-cutting defects нашли поздно.
7. External reviewer wording местами превращало Opus в final authority; локальный source позже опроверг часть предпосылок.
8. Первая Claude Code проверка с пустым tools surface была ошибкой invocation и правильно не вошла в acceptance.
9. Rule-frontmatter hardening не обновил два positive test fixture.
10. Синтетические verification/eval records названы слишком похоже на executed proof.
11. Worklog переписал принятую историю вместо append-only supersession.
12. Exact-name test filter однажды запустил zero tests, но промежуточный
    результат выглядел как verifier activity.
13. PF1 wrapper получил 60 s вместо предусмотренных 600 s.
14. OpenCode agent скопировал статический UUID из server error example;
    этому помог misleading API example.
15. Ошибочные refspec/unsupported structural-search syntax были command/tool
    errors, а не findings о продукте.

### Ошибки внешних систем, не Eliot product

- DeepSeek/OpenCode 503 queue full;
- истёкшая Claude CLI auth;
- Claude Desktop UI hydration/desync частично host/control-plane issue;
- Antigravity terminal stale error после recovery.

### Ошибка текущего audit controller

Первый workspace test был запущен с двухминутным outer shell cap. Wrapper
потерял stream/exit code, хотя cargo child продолжил и завершился. Этот результат
был отброшен; доказательный repeat выполнен с длинным пределом и естественным
exit code. Product verdict на потерянном прогоне не основан.

### Что мы действительно не знаем

- live reproduction WAL-loss revision rollback;
- hostile same-ID cross-project mutation;
- cross-process lost update в JSON work state;
- полный provisioned ignored MCP suite на reconciled head;
- cold recovery и p95 scale на текущем combined build;
- результат real provider/ALE/Future eval families;
- поведение единого head после безопасной интеграции final-v11 и переработанного cognitive slice;
- свежий Claude paid-model E2E для final-v11.

## 13. Почему проект пришёл в это состояние

1. Архитектура росла быстрее, чем acceptance decomposition.
2. Большие slices объединяли runtime, tests, docs, installers и provider work.
3. Была сильная component verification, но слабая release-state reconciliation.
4. Branch/worktree/install artifacts не имели одного enforced canonical head.
5. Документы одновременно служили vision, implementation spec, worklog и status.
6. Evidence записывалось много, но почти не проходило promotion до supported/verified memory.
7. Agent intelligence компенсировал tool errors локально, но не мог заменить missing project/task authority.
8. Expensive/ignored live tests были вынесены из обычного feedback loop и перестали защищать release постоянно.

### Историческая хронология

| Ref | Событие | Реальный статус |
|---|---|---|
| b5c84d4 | Первичный импорт, около 196k строк | Слишком крупный исходный срез |
| 5ef12fc, a80f0fe, 7184d48 | Truth normalization/current-future split | Правильная коррекция |
| eba774a, bccb334 | UL-12 certification и merge main | Historical component pass |
| bfea61a…90ad9cc | C1–C5 | Локально приняты |
| 94af919, 8c7cd26 | R01 exact run и handoff | FAILED_VERIFIER по latency |
| 77b1b87 | COG-00 truthful completion | Phase 0 accepted |
| f3cb22f, 97e8420 | C7-03A/B | Accepted |
| 53817fa…bf2695d | C7-03C Block A | Accepted |
| b93a937 | C7-04A | Checkpoint, NOT ACCEPTED |
| 33e7ae3, b4ec015 | Codex default/startup | Current branch HEAD |
| 5262453…a322970 | Host/plugin repair lineage | Fleet installed, acceptance open |
| current dirty | Exact old blobs + cognitive rollback/rework | UNSAFE_TO_COMMIT_AS_A_UNIT |

## 14. Рекомендуемый план

### Немедленно — release truth

1. Запретить shipment/current-completion claims до удаления P0 fallback.
2. Не коммитить dirty tree целиком.
3. Разложить 74-file diff по provenance buckets:
   docs snapshot, cognitive candidate, deleted runtime/tests, host lineage,
   generated artifacts, local .eliot history.
4. Выбрать один canonical branch и интегрировать final-v11 через reviewable commits.
5. После интеграции обновить graph/status manifest на exact commit.

### P0/P1 correctness

6. Удалить ungrounded completion/cognitive public paths.
7. Добавить canonical scope_head recovery и transactional monotonic CAS.
8. Запретить cross-project overwrite существующего record ID.
9. Реализовать checksummed migration ledger/lease/backup/receipt.
10. Сделать recall_l0 strict AtLeastRevision fail-closed.
11. Сгенерировать public MCP schemas из canonical typed inputs.
12. Восстановить observability identity/hash/schema validation.

### Cognitive/UL

13. Перестроить Phase 2 небольшими accepted blocks:
    one engine runtime, immutable snapshot, restart-safe pending,
    memory-only PreToolUse, bounded PostToolUse, then compiler.
14. Не возвращать старый dual-owner runtime.
15. Не обходить collision random path или ослаблением validation.
16. Реализовать utility projection только с explicit verifier/field gate.

### Host/integration

17. Сделать Codex doctor fail-closed.
18. Использовать collision-resistant repository identity в OpenCode.
19. Ограничить OpenCode child deadline/environment.
20. Добавить transaction/journal/CAS/rollback для OpenCode.
21. Сделать Claude surface transition transactional.
22. Убрать misleading project-aware Antigravity API либо реально bind authority.

### Tests/CI

23. Исправить Antigravity frontmatter fixtures и получить active 310/310.
24. Добавить strict clippy в CI.
25. Добавить отдельный provisioned release gate для ignored MCP/live tests.
26. Убрать fixed ports и уменьшить self-rerun latency.
27. Добавить WAL-loss, same-ID/project, split-writer, restart-pending и
    observability-mismatch adversarial tests.

### Docs/memory

28. Восстановить normalized maintained docs, snapshot оставить только external/historical.
29. Разделить TARGET/IMPLEMENTED/VERIFIED/ACCEPTED/HISTORICAL.
30. Генерировать status из commit-bound acceptance manifest.
31. Ограничить controller/L2 output и duplicate/rank traces.
32. Починить default recall projection lag 82 -> 188.
33. Провести curation: duplicates/supersession/task freshness.
34. Связать observations/claims с TaskContract evidence и verifier runs.
35. Продвигать memory claims только через exact evidence и verifier linkage.

## 15. Предлагаемые GitHub issues

Не создавались автоматически. Рекомендуемый backlog:

1. P0 — Remove ungrounded CompletionGate and CognitiveGate MCP fallbacks.
2. P0/P1 — Reconcile final-v11, cognitive branch, main and dirty provenance.
3. P1 — Recover sequence from canonical head and enforce monotonic CAS.
4. P1 — Reject cross-project canonical record-ID collision.
5. P1 — Add versioned checksummed migration ledger.
6. P1 — Make RecallL0 AtLeastRevision strict and notification-based.
7. P1 — Generate TaskContract/public MCP schemas from canonical types.
8. P1 — Restore observability envelope identity validation.
9. P1 — Rebuild UnderstandingRuntime as small accepted blocks.
10. P1 — Implement WorkLease/WorktreeLease epochs and provider role binding.
11. P1 — Separate synthetic verification plan from executed verification.
12. P1 — Repair Antigravity test fixtures after frontmatter enforcement.
13. P1 — Add clippy and provisioned MCP gates to CI.
14. P1 — Make Codex doctor verify exact installed plugin state.
15. P1 — Harden OpenCode identity, hook and install transaction.
16. P1 — Bound controller/current_state/fetch_l2 output.
17. P2 — Transactional Claude surface switch.
18. P2 — Exact runtime directory ACL postcondition.
19. P2 — Cleanup/secret-scan legacy pending_injection.
20. P2 — Generate commit-bound capability/status docs.
21. P1 — Repair default recall projection lag and strict freshness.
22. P1 — Reconcile eight open 0/2 TaskContracts with exact evidence.
23. P1 — Enforce candidate freshness and duplicate suppression.
24. P1 — Bind CodeCortex project UUID to the actual Git repository.
25. P2 — Paginate/bound recall rank trace and current_state.
26. P2 — Stabilize module IDs and attribute incidents to project/evidence.

## 16. Acceptance classification

### Аудит

- Все пять crate проверены source-level отдельными агентами.
- Current dirty и final-v11 проверены раздельно.
- Cargo/check/clippy/test evidence собрано.
- Docs/history/host/Eliot/code graph включены.
- Критические claims имеют source/test/handle evidence.
- Product files не изменялись.

Статус аудита: VERIFIED. Eliot writeback и exact readback оформляются как
отдельный delivery receipt, чтобы не создавать самореферентный hash отчёта.

### Продукт

Final status: **NOT_ACCEPTED / PARTIAL_PROGRESS**.

Запрещённые формулировки:

- ELIOT complete;
- cognitive layer certified now;
- final-v11 full-suite green;
- main is current installed source;
- healthy runtime means verified memory;
- exact readback means TaskContract complete.

Корректная формулировка:

> ELIOT — работающая и архитектурно содержательная pre-alpha multi-host memory/governance system. Host fleet и множество core mechanisms реально функционируют, но canonical release provenance, completion truth, cognitive Phase 2, canonical integrity, full provisioned verification и governed memory maturity ещё не закрыты.

## 17. Evidence index

Git:

- main: bccb334021749854df1c10733d0e2fadd4b704ca
- cognitive HEAD: b4ec01513c7ef7694e91a16dfcf7998bef7c9cba
- final-v11: a32297048c89862097a3a40d7c3f8127667b80fd
- H6 fix: b44ae9641e10d4d48393304a9a1745472bdc9b50
- repository: https://github.com/UnknownAlienHuman/eliot-memory-os
- compare: https://github.com/UnknownAlienHuman/eliot-memory-os/compare/main...codex/all-host-plugin-repair
- existing issue 7: Claude Desktop UI/response desync
- existing issue 8: task freshness/binding/output
- existing issue 9: Antigravity stale terminal state

Eliot:

- project: 87731db9-1e51-8fde-a4db-222705d7d03a
- prior current-worktree observation:
  observation:871ebf9f-806b-422a-afd5-6b0880986da1
- prior retrospective observation:
  observation:ded98b7f-ae35-48ab-bdd1-16a35b3bb1ff
- prior C7 blocker claim:
  claim:0fb70f96-1d84-46af-a9d5-ec9998b7dfe5
- final-v11 closeout observation:
  observation:b70a4198-a502-5eec-93d6-fd2684564dfd

Code graphs:

- eliot-memory-os-audit-20260805-current-worktree
- eliot-memory-os-final-v11

Primary docs:

- docs/architecture/COGNITIVE_RUNTIME_INVARIANTS.md
- docs/architecture/COGNITIVE_COMPLETION_V2_WORKLOG.md
- docs/architecture/COGNITIVE_CAPABILITY_MATRIX.json
- docs/architecture/UNDERSTANDING_LAYER_STATUS.md
- reports/audit/ELIOT_MEMORY_OS_RETROSPECTIVE_AUDIT_20260803.md

## 18. CompletionProof аудита

    task_goal: полный read-only аудит ELIOT Memory OS
    source_states:
      - current dirty worktree at b4ec015
      - committed cognitive HEAD b4ec015
      - published final-v11 a322970
      - main bccb334
      - installed multi-host fleet
    verified:
      - five-crate source audit
      - git lineage and dirty diff
      - current quick/clippy/test
      - final-v11 clean quick/clippy/test
      - docs hash/snapshot comparison
      - live Eliot health/corpus/incidents/exact L2
      - exact current and final-v11 code graphs
      - host installed-state evidence
    not_verified:
      - full provisioned ignored MCP suite on reconciled head
      - live WAL-loss and hostile project collision reproductions
      - real external provider review through Eliot
      - fresh Claude paid-model final-v11 E2E
    product_status: NOT_ACCEPTED
    dirty_tree_status: UNSAFE_TO_COMMIT_AS_A_UNIT
    audit_files_changed:
      - reports/audit/ELIOT_FULL_PROJECT_AUDIT_20260805.md
