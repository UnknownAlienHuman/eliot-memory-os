# Eliot V3 — реестр анализа

**Статус на 2026-10-26 · Architecture draft.10 / Implementation draft.31 / Cognition draft.14 / Inference Contract 0.10; controller authority `613ea6b5ff6389c7629a988e271477ee45c9d2c1`; активный рабочий реестр, не runtime gate.**

Это **единственный активный реестр** V3. Он хранит текущее решение, границу доказательства, оставшийся разрыв и следующий connected step. [AUDIT](AUDIT.md) и [AUDIT-MAP](AUDIT-MAP.md) сохраняют исходные доказательства и stable dispositions; новый проход обновляет этот файл, а не создаёт ещё один отчёт.

## 1. Статусы и правила

| Статус | Значение |
|---|---|
| `CHECKED` | Указанный source/design scope прочитан и вывод согласован. Не означает работающий runtime. |
| `DECIDED` | Для V3 выбрано решение; код или живой прогон отсутствует. |
| `PARTIAL` | Проверена часть connected edge; остаётся материальный непроверенный участок. |
| `GAP` | В caller→owner→result/unknown→consumer пути отсутствует связь. |
| `OPEN` | Нужно решение или чтение источника. |
| `BLOCKED` | Требуемый predecessor/источник недоступен или не реализован. |
| `NOT SELECTED` | Механизм не нужен выбранной конструкции. |
| `NOT QUALIFIED` | Артефакт найден, но требуемый живой прогон не выполнен. |
| `SUPERSEDED` | Решение относилось к прежнему baseline и заменено current authority. |

Правила:

- README, DTO, fixture, receipt, CI или compilation не дают runtime `CHECKED`;
- `IMPLEMENTED` появляется только после real input→operation→durable result/typed unknown→consumer→restart/readback;
- новый механизм не вводится без named caller, owner, result/unknown и consumer;
- controller V1 используется только как явно названный donor;
- Memory inference реализуется только поверх current controller V2 после его foundation;
- Git history хранит подробную хронологию; этот файл хранит текущее состояние.

## 2. Критические текущие факты

### 2.1 Controller V2 authority и blockers

| ID | Объект | Статус | Текущее решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-123 | Current controller authority | `CHECKED` | Authority — `main@613ea6b5`, merged PR #198. V2 = fresh JSON-RPC + SQLite WAL + global external `WriteId`; current Rust/`swarm-client`/generic Operation stack — V1 legacy pending deletion. | Не добавлять Memory functionality в V1. |
| R-130 | Controller roadmap status | `CHECKED` | `docs/roadmap.md` — единственный status tracker; L0.1–L1.11 все unchecked. PR #198 — specification only, не runtime. | Controller сначала реализует L0/L1. |
| R-131 | Binding revision allocator / schema | `GAP`, `BLOCKED` | Issue #200: current `current+1`/revision-1 allocation collides after failed attach. Дополнительно найдены cancelled initial launch, cancelled queued resume и failed/unknown first observe attach. Pointer-absent later revision конфликтует с current schema CHECK, требующим supersedes для every revision>1. PR #201 исправляет только ошибочные fixtures и уже green, allocator не закрыт. | Закрыть #200 в core/API/config/decisions/schema validator до L0/L1 code. |
| R-048 | `inference.text/embed` runtime | `BLOCKED` | Current V2 methods/runtime отсутствуют; issue #199 blocked on L0/L1 и #200. | После foundation реализовать P1a Contract 0.10. |

### 2.2 Memory inference contract

| ID | Объект | Статус | Текущее решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-047 | One-shot ownership | `CHECKED` design / `NOT IMPLEMENTED` | Memory owns semantic job/source/recipe/decode/publication; controller owns authenticated physical call/readback/copies. | P1a after V2 foundation. |
| R-053 | Narrow caller | `DECIDED` / `NOT IMPLEMENTED` | Dedicated `memory_inference`; no owner, Agent, automation, plugin or no-token fallback. | Registration + denial matrix. |
| R-117 | Stable caller continuity | `CHECKED` design / `GAP` runtime | Stable `client_id = memory:<random-installation-id>` owns calls across token rotation and Memory rollback. | Pre/post-rotation old-call read/release. |
| R-125 | Global `WriteId` call identity | `DECIDED` / `NOT IMPLEMENTED` | Call identity = global ULID + exact `client_id` + method + canonical semantic payload; call ID equals WriteId. | Receipt/call transaction. |
| R-126 | Minimal V2 durable state | `DECIDED` / `NOT IMPLEMENTED` | Reuse `write_receipts`; add only `memory_inference_clients`, `inference_calls` and private call-owned files. | Schema/runner/copy lifecycle. |
| R-132 | Guaranteed inference retention | `DECIDED` / `NOT IMPLEMENTED` | Normative guarantee is monotonic `retain_after_seq`, not observed `earliest_retained_seq`. Registration owns `last_admission_seq` + `retain_after_seq`; list before cut returns `history_gap` even if rows happen to remain. | Add high-water/list/retention.advance exactly as Contract 0.10. |
| R-133 | Memory external WriteId generator | `DECIDED` / `NOT IMPLEMENTED` | One locked atomic installation-scoped monotonic ULID state outside rollback roots. Advance state before job record/send and at least daemon floor/current monotonic time. | Implement Windows durable state and rollback cases. |
| R-134 | Auxiliary mutation identity | `DECIDED` / `NOT IMPLEMENTED` | Cancel, release and retention advance each receive durable pre-send WriteId. Out-of-target cleanup uses ordinary durable Memory cleanup job/record. | Add fields/operation path; no new table. |
| R-135 | Private credential publication | `DECIDED` / `NOT IMPLEMENTED` | Controller-local owner publishes derived token only to admitted create-new/no-reparse private destination with ACL + file/parent durability. Output path is presentation, not registration identity. | Qualify install/reissue/lost reply/path negatives. |
| R-128 | Post-backup external-work inventory | `DECIDED` / `NOT IMPLEMENTED` | Backup stores controller high-water and guaranteed retain cut; restore pages one fixed `(backup_high_water, inventory_high_water]` membership and dispositions every out-of-target call. | Stable cursor/list and cleanup jobs. |
| R-129 | Retention gap | `DECIDED` / `NOT IMPLEMENTED` | `backup_high_water < retain_after_seq` means `history_gap`; observed earliest row is diagnostic only. | Update all owner docs and issue #199 implementation. |

### 2.3 Normative synchronization

| ID | Объект | Статус | Текущее решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-024 | Normative synchronization | `PARTIAL` | Contract 0.10 and this registry use controller `613ea6b5`, issue #200, `retain_after_seq`, installation WriteId state and auxiliary mutation IDs. Architecture 10 / Implementation 31 / Cognition 14 / README still contain Contract 0.9, stale `c8c0ee1` and `earliest_retained_seq` wording. | Synchronize existing owner docs in-place; no errata/second contract. |
| R-076 | Base/Store synchronization | `CHECKED` design / `NOT IMPLEMENTED` | Host/capture/Store/Windows/backup physical baseline remains internally selected; inference changes do not block Base. | Keep Base path independent while syncing inference text. |

## 3. Product, Base и memory semantics

| ID | Объект | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-001 | Product ownership | `CHECKED` design | Host/controller external work; Memory daemon semantics/state; supervisor privileged installation/process effects. | Не возвращать Task/provider stack в Memory. |
| R-002 | Process family / idle drain | `DECIDED` / `NOT IMPLEMENTED` | Supervisor + daemon + active Store + max one candidate; retained identities; finite drain. | Slice 0 process/IPC/shutdown. |
| R-003 | Continuation address | `DECIDED` | Project/workspace + task or actor/session; path/branch/HEAD are environment. | Fork/two-workspace/late-result cases. |
| R-004 | Context packet identity | `CHECKED` design / `NOT IMPLEMENTED` | Rendered bytes/digest + exact revisions + gaps in ordinary data. | Real host emission/readback. |
| R-005 | Structured correction | `DECIDED` | Correction observation + revision/history + saved result atomically. | Conflict/replay/readback. |
| R-006 | Six Memory tables | `CHECKED` design / `NOT IMPLEMENTED` | `stream`, `observation`, `memory`, `memory_history`, `link`, `job`; strict schema, fixed queries, DTOs/indexes. | Migration 0001/query corpus. |
| R-007 | Current/history | `DECIDED` | Exact version handles; no fall-forward or predecessor resurrection. | Publication/restart readback. |
| R-008 | Compound grounds | `PARTIAL` | Required groups, alternatives and advisory support separated. | Reducer/cycle/erase/concurrency. |
| R-009 | Retrieval arms / packing | `PARTIAL` | Exact/address/lexical/vector/relation arms independent. | Real plans/limits/noise/exceptions. |
| R-010 | Processing-method consumer | `DECIDED` | Job freezes recipe revision; later consumer must read result. | Changed later context. |
| R-011 | Reuse/disclosure | `DECIDED` | Origin, reuse scope and disclosure independent. | Scoped queries/reduction. |
| R-012 | Native hook capture | `CHECKED` design / `NOT IMPLEMENTED` | Finite Claude event profile. | Installed-build qualification. |
| R-013 | Native context delivery | `CHECKED` design / `NOT IMPLEMENTED` | Actual packet crosses host boundary; prepared/emitted/use distinct. | Resume/compact/fork/subagent. |
| R-019 | Backup/restore | `CHECKED` physical design / `NOT IMPLEMENTED` | Typed backup, brief spool cut and exact rollback; controller continuity now requires high-water + retain cut + stable list inventory. | Windows round-trip and external-work cases. |
| R-020 | Erasure/reappearance | `PARTIAL` | Monotonic fence + physical controlled-copy traversal; provider effects external. | All roots/backups/spool/controller copies. |
| R-021 | Recursive improvement | `PARTIAL` | Diagnose concrete failed edge; no intelligence score. | Source→revision→later context. |
| R-022 | Disagreement/anticipation | `CHECKED` design | Alternatives + grounds + cheapest distinguishing observation. | Ordinary records after Base. |
| R-023 | Control/status/inbox | `DECIDED` | Daemon public control; supervisor closed privileged effects; status from readback. | Operation/readback paths. |
| R-025 | Interpretation triggers | `DECIDED` | New committed input/correction/question; bookkeeping does not self-trigger. | Inspect enqueue callers. |
| R-026 | Active/pending jobs | `DECIDED` | One active + one coalesced successor; waiting ≠ retry. | Arrival/shutdown modes. |
| R-028–R-045 | Learning/retrieval/history details | `DECIDED` or `PARTIAL` as previously recorded | Recipe bootstrap, outcome attribution, coverage, useful Base, vector mapping, commitments, source continuity, bounded reads, curation/split/forgetting and typed first episode remain selected. | Implement only after Base prerequisites; no new platform. |

## 4. Store, Windows и backup audit

| ID | Объект | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-071–R-081 | Legacy Base/packet/exact-open audit | `CHECKED` selected paths | V2 Memory forwarder/spool/packet/broad-read defects identified; V3 uses one immutable command, real replay, actual host packet and exact handle/cursor. | Base Slices 1–2. |
| R-082 | SurrealDB Rust SDK | `NOT SELECTED` baseline | SDK/MSRV/license/dependency cost does not fit current baseline; bounded remote client selected. | Reconsider only with exact preflight. |
| R-083 | SurrealDB Windows identity | `CHECKED` release identity / `NOT QUALIFIED` runtime | Exact 3.3.4 asset/tag/size/SHA retained. | Download/hash/PE/signature/live Slice 0. |
| R-084–R-100 | Store transport/schema/durability | `CHECKED` design / `NOT IMPLEMENTED` | Query-only authenticated WS, dedicated owner, strict schema, conflicts, no-replace files, root/bootstrap/roles/readiness, sync=every, closed env and explicit DTOs. | Slice 0 live qualification. |
| R-101/R-107 | Backup cut and replay barrier | `CHECKED` design / `NOT IMPLEMENTED` | Brief publication cut, active replay drain, exact typed pages, deletion/spool continuity. | Crash/in-flight/mismatch cases. |
| R-102–R-106 | Endpoint/IPC/launch ownership | `CHECKED` donor/design / `NOT IMPLEMENTED` | Origin not auth; listener+peer owner; mutually attested relay pipe; retained executable/root identity; cancellation-safe socket owner. | Windows implementation. |
| R-108–R-116 | Privileged lifecycle/rollback/ACL/rotation | `CHECKED` design / `NOT IMPLEMENTED` | Inherited supervisor channel, expected-generation selection, exact rollback not invented merge, root/backup controlled copies, session revocation and previous-generation backpressure. | Slice 0 and Base maintenance. |

## 5. Development-system findings

| ID | Объект | Статус | Текущее решение |
|---|---|---|---|
| R-058–R-067 | Delivery collapse / bureaucracy | `CHECKED` | Connected behavior is denominator; one ledger/integrator; cheap preflight; no crate/process/object family per noun; replace superseded authority. |
| R-049 | Verification order | `DECIDED` | Production code first; fmt + minimum changed-package Clippy after coherent increments; broad suite after connected product. |
| R-059 | Append-only authority | `CHECKED` design | Replace stale active text in-place; do not add errata/report layer. |

## 6. Source coverage added in this pass

| ID | Источник | Статус | Граница вывода |
|---|---|---|---|
| S-056 | Controller `main@613ea6b5`, merged PR #198 and `docs/roadmap.md` | `CHECKED` | Current V2 authority; specification only; all L0/L1 unchecked. |
| S-057 | Controller issue #200 + draft PR #201 + CI | `CHECKED` | Validator fixture fix is green; allocator/pointer/schema defect remains. Additional launch/resume/first-observe cases recorded in issue comment. |
| S-058 | Controller issue #199 and Memory Contract 0.9 comparison | `CHECKED` | Issue's `retain_after_seq` is stronger/correct; Contract 0.9 earliest-retained wording was insufficient. Audit comment records allocator/list/WriteId/credential-output gaps. |
| S-059 | Memory Contract 0.10 | `CHECKED` design | Current selected cross-repository boundary; no runtime implementation. |

Existing source records S-001–S-055 remain historical evidence with their previous exact scope; no donor is qualified wholesale.

## 7. Current queue

| Priority | Работа | Закрывает |
|---|---|---|
| P0 | Synchronize Architecture/Implementation/Cognition/README/root entry points with Contract 0.10: controller `613ea6b5`, #200 blocker, `retain_after_seq`, `last_admission_seq`, fixed list snapshot, external WriteId state and auxiliary mutation IDs. | R-024, R-123, R-129–R-135 |
| P0 | Controller #200: finish allocator/schema/API/config/decision fix including cancelled launch/resume and pointer-absent first attach; merge only after validators prove named cases. | R-131, S-057 |
| P0 | Keep issue #199 blocked until controller L0/L1 + #200; fold retention/list/WriteId findings into implementation contract before code. | R-048, R-126, R-132–R-135 |
| P1 | Memory Slice 0 physical qualification: exact Windows assets/roots/process/IPC/Surreal/Store/files/backup/rollback/erasure/rotation/shutdown. | R-002, R-006, R-019–R-020, R-071–R-116 |
| P1 | Base Slice 1: event→Store/spool→replay→restart→exact open. | R-001–R-013, R-071–R-107 |
| P1 | Base Slice 2: Claude relay, continuation, lexical retrieval, packet emission, notes/corrections/commitments and maintenance. | R-003–R-045 |
| P1 | Controller V2 L0/L1 implementation under its roadmap. | R-130–R-131 |
| P1 | P1a Memory inference after foundation: principal, WriteId state, receipts/calls/copies/runner/read/release/retention/inventory and one later context consumer. | R-047–R-057, R-117, R-124–R-135 |
| P2 | P1b rotation; embeddings; documents/views/Research/other hosts as independent increments. | R-015–R-018, R-031–R-032 |
| Final | Broad deterministic/live/platform/load suites only after connected product. | R-049 |

## 8. CI state

Memory PR #5325 remains documentation-only and currently fails before MergeCompile:

```text
base-owned workflow oracle       PASS
shared documentation evidence   FAIL: EMPTY_DOCUMENTATION_EVIDENCE
MergeCompile                     SKIPPED
```

The same run reports `surrealdb_provisioner = provision_failed`. No fabricated evidence block is accepted. CI failure is not a runtime/design proof and does not alter the implementation order.

## 9. Последние изменения

| Дата / commit | Изменение |
|---|---|
| 2026-10-26 / `abd2d046` | Architecture 10 / Implementation 31 / Cognition 14 / Contract 0.9 rebased from controller V1 to V2; backup spool cut and external-work inventory. |
| 2026-10-26 / issue comments #200/#199 | Added allocator edge cases and retention/WriteId/credential-publication findings to controller owners. |
| 2026-10-26 / `ec36adbb` | Contract 0.10: current authority, `retain_after_seq`, per-client allocator, stable list window, rollback-safe WriteId generator and durable auxiliary mutation IDs. |
