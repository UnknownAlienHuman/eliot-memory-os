# HANDOFF — рой ELIOT, остановка 02.10.2026

Root (Claude Opus 5.5) остановил рой по приказу владельца (карта блоков + недельная квота root 95%). Этот файл —
для того, кто продолжит: где что лежит, как поднять, на чём остановились, что ждёт решения. План продолжения —
`CONTINUATION.md` (отдельный PR продолжения), уроки — `RECOMMENDATIONS.md`, журнал решений и инструкция по эксплуатации —
`MANAGER-BRIEF.md`, карта блоков — `BLOCK-MAP.md` / `BLOCK-MAP.tsv`.

## 1. Где что лежит
- Репозиторий: `C:\Development\Rust\projects\eliot-memory-os` (GitHub `UnknownAlienHuman/eliot-memory-os`). Корневой
  checkout принадлежит владельцу: его ветку, `.swarm\`, `AGENTS.md` и незакоммиченные файлы не трогать.
- Рой: `C:\Development\Rust\projects\eliot-swarm\` — worktree линий `M-<LANE>` (ветка `lane/<LANE>`), каталоги сборки
  `targets\<LANE>`, управление `control-20260923-impl\` (скрипты в `v2\`, уборка в `cleanup\`).
- Профиль Codex-линий: `C:\Users\kleym\.codex\lane.config.toml` (суб-агенты gpt-6-luna, предел 5 потоков).
- Профиль сборки роя: `eliot-swarm\.cargo\config.toml` (без sccache; debug line-tables-only, зависимости без debug).

## 2. Точки входа (скрипты `control-20260923-impl\v2\`)
| Что | Скрипт | Как запустить |
|---|---|---|
| Раннер линии (сессия за сессией, очередь из SECTORS.json) | `Run-Sector.ps1` | `pwsh -File Run-Sector.ps1 -Worker <L>`; стоп: файл `v2\STOP` или `active:false` в SECTORS.json |
| Сессия OpenCode | `oc_run.py`, `oc_http.py` (prompt/steer, background, inbox) | вызывает раннер |
| Сессия Codex (поток общего app-server, цель) | `Launch-Codex.ps1` → `codex_as.py run`; steer: `codex_as.py steer --inbox workers\<L>\logs\steer --text "... then CONTINUE in this turn"` | app-server: `codex app-server daemon start` (UAC) |
| Command Code / Muse Code | `Launch-CommandCode.ps1`, `Launch-MuseCode.ps1`, `muse_as.py` | вызывает раннер |
| Бриф линии | `TEMPLATE-SECTOR.md` (правила §0–§3), `state.py sector-queue <L>` | раннер подставляет очередь |
| Приёмка (10 слотов) | `Merge-Daemon-v8.sh` (`REVIEW_SLOT=<n>`), `Run-Slot.sh <n>`, `slot_guardian.py`; стоп: `v2\slots.stop`, `Stop-DaemonV8-Safely.ps1` | журнал `v2\daemon.log` |
| Гейт поставки | `pr_evidence.py --open <n> <sha>` (пункты не MET/TEST-PHASE/BLOCKED #n держат поставку), `Make-PR2.sh`, `Review-Branch2.sh` | вызывает демон |
| Закрытие задач | `closure_pass.py --budget 40 --apply` (раз в час) | журнал `v2\closure-pass.log`, `closed-by-root.log` |
| Аудит владельца → чек-листы | `ingest_audit.py`, `apply_ccv.py` (раз в 15 мин) | `audit-ingest.log`, `ccv-applied.log` |
| Проверяющий (OR) | `TEMPLATE-CCV.md` | бриф OR |
| Вопросы-формы OpenCode | `answer_forms_http.py` (раз в 15 мин) | |
| Напоминания линиям | `Remind-Subagents.py` (раз в 5 мин; цель 4 писателя, Codex 5, Muse 8) | |
| Наблюдение | `Agent-Watch.py`, `Report30.sh 3600` (часовой отчёт), `lane_scoreboard.py` | |
| Сторожа | `Codex-Server-Guard.ps1` (перезапуск app-server после 2 промахов), `Surreal-Orphan-Sweep.ps1` (сироты surreal.exe, git fsmonitor) | |
| Уборка (слот 5 ч) | `cleanup\Run-Maintenance.ps1`, `cleanup\MAINT-BRIEF.md`, `cleanup\Sweep-Targets.py`, `Fold-ArchiveWip.sh` | журнал `cleanup\ledger.tsv` |
| Карта блоков | `BLOCK-MAP-BRIEF.md`, `blockmap_build.py [--coverage]` | `v2\BLOCK-MAP.md/.tsv` |
| Финальная линия | `workers\FIN\FIN-BRIEF.md` | см. §4 |

## 3. Состояние линий на остановке
| Линия | Модель | Задача | Ветка | Сдача | Последний вердикт приёмки |
|---|---|---|---|---|---|
| W1 | OpenCode Go space-bunny | #1968 #1968 | lane/W1@9c2be5056 | PUSHED | HOLD->BACK #1968 lane/W1: new-broken-targets:[error: could not compile `eliot-agent-bridge` (lib test);] new-c |
| W2 | OpenCode Go space-bunny | #262 | lane/W2@097ce32fa | PUSHED | HOLD->BACK #262 merge failed [rv2] |
| W3 | OpenCode Go space-bunny | #686 | lane/W3@69ddb25ab | PUSHED | HOLD->BACK #686 merge failed [rv6] |
| W4 | OpenRouter space-bunny-alpha | #1884 | lane/W4@4853039ac | PUSHED | HOLD->BACK #1884 lane/W4: new-clippy:[+1  bins/eliot-kernel/src/daemon_process_launch.rs/error: unused `self`  |
| OR | OpenRouter space-bunny-alpha (проверяющий) | - | - | - | - |
| CS1 | Codex gpt-6.1-sol | #1814 | lane/CS1@908169709 | отправлена без сдачи | HOLD->BACK #1814 fix/1814-registry-impl-W1c: conflict-with-main(rebase-and-resolve) review-incomplete [rv10] |
| CS2 | Codex gpt-6.1-sol | #1774 | lane/CS2@6c08e014b | отправлена без сдачи | HOLD->BACK #1774 feat/1774-requalify-current-W4k: new-broken-targets:[error: could not compile `eliot-installa |
| CS3 | Codex gpt-6.1-sol | #1115 | lane/CS3@693a1c945 | PUSHED | MERGED #1115 pull/5016 -> 1115 -> CODE-COMPLETE remaining=0 problems=0 stitch=6 [rv7] |
| CB | Command Code space-bunny-alpha | #1888 | lane/CB@21edcced4 | PUSHED | HOLD->BACK #1888 lane/CB: new-broken-targets:[error: could not compile `eliot-app` (bin "eliot-governor" test) |
| CB2 | Command Code space-bunny-alpha | #787 #880 | lane/CB2@9c2eb2d1a | отправлена без сдачи | HOLD->BACK #787 fix/787-dependency-proof-CB1: red-flags(todo!/unimplemented!/NoOp/InMemory/shim in added lines |

После приказа 13:15 W1–W4 исправили причины возврата и сдали заново (W4 — lane/W4@6b45330d3); вердикты приёмки по ним — в `v2/daemon.log` после 13:40. #1115 (CS3) влита 13:30.

Полные строки HANDOFF линий — `LANE-HANDOFFS.md`. Карта блоков — `BLOCK-MAP.md` (577/577 задач).

## 4. Остановка и уборка (выполняется)
1. 12:45 — `v2\STOP` и `v2\WRAP-UP`; приказ всем 10 линиям: доделать текущую задачу и долю карты, убрать мусор,
   строка `HANDOFF <L>`. Остановлены напоминания и make_task.
2. Линия **FIN** (Codex gpt-6.1-sol, суб-агенты gpt-6-luna max, цель через thread/goal) принимает работу линий
   (`workers\FIN\lanes\<L>.md`), делает опись (`FIN\INVENTORY.tsv`) и аудит веток GitHub (`FIN\REMOTE-AUDIT.tsv`).
3. Когда все линии дадут HANDOFF: root останавливает свои циклы (приёмка, закрытие, аудит, формы, сторожа, отчёты),
   службу OpenCode, затем создаёт `v2\FIN-GO`.
4. FIN: всё неслитое → `archive-wip/*` → `Fold-ArchiveWip.sh` → `archive/wip-preserved-20260925` (проверка предков),
   затем удаляет (разрешено владельцем 02.10 12:20): локальные ветки и worktree, все ветки GitHub кроме `main` и
   `archive/*`, сессии OpenCode полностью, кэш загрузок Cargo, сборки, кэши, журналы завершённых потоков Codex,
   мусор линий. Итог — `workers\FIN\FIN-REPORT.md`.
5. Задача планировщика Windows `EliotWatchdog` (прежний root, 18.09) требует прав администратора — отключает
   владелец: `Disable-ScheduledTask -TaskName EliotWatchdog` (или `Unregister-ScheduledTask -TaskName EliotWatchdog
   -Confirm:$false`) в PowerShell от администратора.

## 5. Открытые проблемы
- **Space Bunny уходит через 3 дня** — на нём 7 из 10 линий (W1–W3, OR, W4, CB, CB2). Остаются Codex, MC (квота с
  05.10 00:00 UTC), Antigravity (мало квоты), Claude.
- **lane/CB** держит ~20 коммитов 8 задач (#1888 #2730 #2565 #1935 #7 #1868 #2857); приказ 11:30 — пересобрать
  ветку под одну #1888. Если не успела — работа уйдёт в архив FIN, задачи разбирать по одной.
- **Дубль механизма CPU rate** в `eliot-platform-windows/process_job.rs`: W4 (#1884) и CB (#1888). Правило: кто влит
  первым, тот остаётся; второй берёт версию main.
- **CI на main** (`ci.yml`, compile-only) был красным по шагу профиля #1914 — проверить на текущем main.
- Предел 5 суб-агентов Codex действует только с новой сессии менеджера.
- Карта блоков: строки без названного блокера и MISSING-CONTRACT без раздела документации — перепроверить (шаг 2
  CONTINUATION).

## 6. Решения, ждущие владельца
Эскалации линий, по которым нет решения root (решения root 02.10 — в MANAGER-BRIEF, строки 10:45–11:30). Каждая — проектное решение, которое не определяют ни задача, ни документация:

- **W1 #1968**: who owns the EXTERNAL NormativePairIdentity seal issuer - I1
- **W1 #1968**: the Blob Store generation boundary - options: (a) BLOCKED blocked_by #14, (b) land the missing launch caller HERE, which would duplicate #14's declared work
- **W1 #1968 - the presented blob root identity is compared VERBATIM against the approved root, so on Windows a separator or case difference between what the store configures and what the manifest holds would refuse every real generation; the alternative is eliot-blob's private ownership_key normalization exported for this comparison. Options**: (a) keep failing closed and let #19 own normalization, (b) export the owner crate's existing normalization and use it
- **W1 #1968 - eliot-ipc cannot name the daemon identity (ACTIVE_DAEMON_CALLER is a private const in two crates) so the producer had to move into the Kernel binary; and the Blob Store generation launch plus its production caller stays BLOCKED blocked_by #19. waiting on**: A3, because B's fail-closed refusal of the five keys means the tree as it stands would refuse every integrated eliotd startup - the pair ships together or B's absence refusal reverts to the recorded-gap form
- **W1 #1968 (no owner)**: should the unkeyed normative-pair SEAL tag ever be satisfied by an external issuer? I1
- **W1 #19 (its own paths)**: the Blob Store generation boundary has no process, no production caller and a root identity whose canonical spelling only eliot-blob may define; I did not invent any of the three
- **W3 #325**: where may the acceptance-item-to-test-id join live - options (a) a new field on the TaskContract acceptance owner record in eliot-store-api, which is storage-owned and would be a record change; (b) a new owner contract for the pla
- **W3 #686**: is the end state for GetAuthorityRevocationHistory a store read handler or Kernel-served history - activating it in the store would be a SECOND route to an answer the Kernel already serves from the retained P-07 ORS, so the catalo
- **W3 #686**: may the thirteenth InfluenceError cause exist at all - a Transition cause is meaningless in a pure graph evaluator whose entry point has no production caller, so minting one would be decorative, and the rules forbid a variant that
- **W3 #2802**: no admitted component resolves an owner-issued BackupArtifactHandle into the exact bytes that handle names, and nothing in the tree or in any open issue decides which component it should be
- **W4 #1884**: the platform's Job Object vocabulary cannot express two of the manifest's four pre-existing limit coordinates - ManifestResourceLimits::validate (pre-existing on origin/main, verified with git show) requires a NON-BLANK job_object
- **W4 #1884 option A/B/C, and the issue number that owns the Module Catalog write path if it is not #18. NO cargo test from this lane (owner 2026-10-02 02**: 45: OR and root run tests)
- **W4 #1884 (second decision, small but it is a durability choice and not mine)**: KernelReconciliationItem::RECORD_TYPE is the literal 'effect_replay_reconciliation' while its table is EFFECT_REPLAY_RECONCILIATIONS, and this delivery REUSES that one record type for a manifest-side restart escalation that names
- **CS1 #1814**: normal register_instrument_registry_from_claim retains TaskSelectionEvidence
- **CS2 #1966**: I3
- **CS3 #267**: transformed-output producer/receipt owner unspecified in comment5881613195; options assign explicit existing owner or retain BLOCKED MISSING-CONTRACT I8 streaming transformation section
- **CB2 #880**: whether crates/eliot-types/tests/** counts as "other crates" under #880 TASK
- **CB2 #880**: whether to keep commit 297a5549d's eliot-types distillation
- **CB2 #880**: who builds the memory measurement payload producer, since without one the cost-disposition arm never fires in production and 880's acceptance is unprovable
- **CB2 #787/#880**: whether the two #866 ContractChallenges get a #866 owner assigned now, since every remaining item on both issues waits on them

Решены root 02.10 (не повторять): #1884 CPU rate через JOB_OBJECT_CPU_RATE_CONTROL, job_object_policy — сравниваемый токен; дубль CPU rate W4/CB — остаётся влитый первым; #1888 identity и admitted generation — BLOCKED (MISSING-CONTRACT I01-06:12 / задача-владелец активации), проверка бинаря по пути пишется; #18 — 2 пути с наследными вызовами остаются consumer surface; #1814 пороги circuit и ContractId→SchemaRef — BLOCKED MISSING-CONTRACT I10.8.3/I10.17.

## 7. Как поднять рой заново (кратко; подробно MANAGER-BRIEF §13)
1. Codex app-server: `codex app-server daemon start` (UAC), затем `Codex-Server-Guard.ps1` в фоне.
2. Служба OpenCode (консоль скрыта: WMI `ShowWindow=0`).
3. Очереди: `SECTORS.json` из плана продолжения; удалить `v2\STOP`; раннеры `Run-Sector.ps1 -Worker <L>`.
4. Приёмка: 10 слотов `Merge-Daemon-v8.sh` + `slot_guardian.py`; закрытие `closure_pass.py` раз в час; аудит
   `ingest_audit.py` + `apply_ccv.py`; формы; напоминания; сторожа; `Report30.sh 3600`.
