# Eliot V3 — реестр анализа

**Статус на 2026-10-27 · Architecture draft.16 / Implementation draft.37 / Cognition draft.20 / Inference Contract 0.15; controller authority `613ea6b5ff6389c7629a988e271477ee45c9d2c1`; активный рабочий реестр, не runtime gate.**

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
| R-130 | Controller roadmap status | `CHECKED` | `docs/roadmap.md` — единственный status tracker; L0.1–L1.11 все unchecked. PR #198 — specification only. | Controller реализует L0/L1 после #200. |
| R-131 | Binding revision allocator/schema | `GAP`, `BLOCKED` | Issue #200: allocator derived from selected pointer/revision-1 assumptions collides after retained failed/unselected candidates. Affected: failed observe→control, cancelled initial launch, cancelled queued resume, failed/unknown first observe attach. Pointer-absent later revision conflicts with current supersedes CHECK. PR #201 fixes only fixtures. | Исправить core/API/config/decisions/schema validator before L0/L1. |
| R-048 | `inference.text/embed` runtime | `BLOCKED` | Current V2 methods/runtime absent; issue #199 blocked on #200 + L0/L1. | Implement Contract 0.15 P1a only after foundation. |

### 2.2 Memory inference contract

| ID | Объект | Статус | Текущее решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-047 | One-shot ownership | `CHECKED` design / `NOT IMPLEMENTED` | Memory owns semantic job/source/recipe/decode/publication; controller owns authenticated physical call/readback/copies. | P1a after V2 foundation. |
| R-053 | Narrow caller | `DECIDED` / `NOT IMPLEMENTED` | Dedicated `memory_inference`; no owner, Agent, automation, plugin or no-token fallback. | Registration + denial matrix. |
| R-117 | Stable caller continuity | `CHECKED` design / `GAP` runtime | Stable `client_id = memory:<random-installation-id>` owns calls across token rotation and Memory rollback. | Pre/post-rotation old-call read/release. |
| R-125 | Global `WriteId` call identity | `DECIDED` / `NOT IMPLEMENTED` | Live call identity = global ULID + exact client + method + canonical payload; call ID equals WriteId. | Receipt/call transaction. |
| R-126 | Minimal V2 durable state | `DECIDED` / `NOT IMPLEMENTED` | Reuse `write_receipts`; add only `memory_inference_clients`, `inference_calls` and private call-owned files. | Schema/runner/copy lifecycle. |
| R-132 | Guaranteed post-cut retention | `DECIDED` / `NOT IMPLEMENTED` | Monotonic `retain_after_seq` protects complete post-cut membership above minimum high-water of published non-retired restorable backups and unresolved preparing/publication-unknown fences. It is not observed earliest row and is not lowered for in-cut dependencies. | Implement high-water/list/retention.advance and controlled-set scan. |
| R-133 | Memory external WriteId generator | `DECIDED` / `NOT IMPLEMENTED` | One locked atomic installation-scoped monotonic ULID state outside rollback roots. Advance before job record/send and at least daemon floor/current monotonic time. | Implement Windows durable state and rollback cases. |
| R-134 | Auxiliary mutation identity | `DECIDED` / `NOT IMPLEMENTED` | Cancel, release and retention advance each get durable pre-send caller WriteId. Proven-unsent auxiliary mutation is retired at backup cut. | Add fields/reconciliation path; no new table. |
| R-135 | Private credential publication | `DECIDED` / `NOT IMPLEMENTED` | Controller-local owner publishes derived token only to admitted create-new/no-reparse private destination with ACL + file/parent durability. | Qualify install/reissue/lost-reply/path negatives. |
| R-128 | Restore external-work inventory | `DECIDED` / `NOT IMPLEMENTED` | Backup stores high-water + retain cut; restore captures fixed `(backup_high_water, inventory_high_water]` membership and dispositions every out-of-target call. | Stable cursor/list + cleanup jobs. |
| R-129 | Retention gap | `DECIDED` / `NOT IMPLEMENTED` | `backup_high_water < retain_after_seq` means `history_gap`; physical row presence is diagnostic only. | Implement and qualify. |
| R-136 | Backup admission closure | `CHECKED` design / `NOT IMPLEMENTED` | Before high-water, one controller-mutation owner is closed/drained and every created call ID becomes `admitted`, `retired_not_admitted` or `admission_unknown`. Release/retention cannot race controlled-set changes. | Implement barrier, exact absence/readback, retired-ID send denial and mutation serialization. |
| R-137 | Cleanup/erase authority | `CHECKED` design / `NOT IMPLEMENTED` | Valid caller uses optional cancel + `release(abandon_for_erasure)`. `inference.erase` is controller-owner-only break-glass; Memory records `owner_action_required` and later owner readback, never owner WriteId/effect. | Implement caller path, owner-action debt and denial tests. |
| R-138 | Retention tombstone vs physical erasure | `DECIDED` / `NOT IMPLEMENTED` | Content/sensitive facts erase immediately, but calls above retain cut keep bounded text-free membership tombstone. Tombstone deletion requires retirement of pinning backups and prior cut advance. | Add erased/abandoned tombstone state and inventory cases. |
| R-139 | In-cut backup dependency release fence | `CHECKED` design / `NOT IMPLEMENTED` | Every admitted in-cut job is `controller_closed` or `controller_dependent`. Dependent calls/copies stay unreleased while any restorable/provisional backup needs them, even below current cut. | Implement controlled-set dependency scan, pre-release recheck and restore/release cases. |
| R-140 | Contract 0.13 provisional fence | `SUPERSEDED` by R-141/R-142 | Final-manifest digest in rollback-local Store job created self-reference and rollback authority loss. | Do not implement 0.13 shape. |
| R-141 | Canonical backup plan digest | `CHECKED` design / `NOT IMPLEMENTED` | Precommit `backup_plan_digest` over explicit immutable plan fields excluding digest itself, publication state and later part/manifest digests. Final manifest repeats plan digest plus actual inventories. | Implement canonical plan codec, digest/readback and mismatch cases. |
| R-142 | Rollback-safe provisional authority | `CHECKED` design / `NOT IMPLEMENTED` | Publish create-new installation-scoped `fence.json` before parts. Valid manifest or durable abort resolves it; ambiguity remains fenced. `preparing|publication_unknown` pin release and post-cut retention. Store job is mirror only. | Implement fence/manifest/abort scan, startup/rollback reconciliation and crash matrix. |
| R-143 | Monotonic published-backup retirement | `CHECKED` design / `NOT IMPLEMENTED` | Published backup leaves restorable set only after create-new durable `retire.json` binding backup/plan/manifest identity. Deleting authority files is not retirement. Unknown/mismatch remains pinned; abort and retire are mutually exclusive. Retirement is not physical erasure. | Implement retire marker, idempotent readback, false-unpin crash tests, restore refusal and later physical cleanup. |

### 2.3 Normative synchronization

| ID | Объект | Статус | Текущее решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-024 | Normative synchronization | `CHECKED` design | Architecture 16 / Implementation 37 / Cognition 20 / Contract 0.15 / V3 README agree on controller `613ea6b5`, mutation/admission/dependency closure, canonical plan digest, installation-scoped publication/retirement authority, release+retention fences, tombstones and cleanup authority. Root/docs entry points are synchronized in the same continuation. | Change all owner docs together when mechanism changes. |
| R-076 | Base/Store synchronization | `CHECKED` design / `NOT IMPLEMENTED` | Host/capture/Store/Windows/backup physical baseline remains synchronized and independent of inference dependency. | Implement/qualify Base first. |

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
| R-019 | Backup/restore | `CHECKED` design / `NOT IMPLEMENTED` | Typed backup, brief spool cut, admission/dependency closure, canonical plan, rollback-safe publication, monotonic retirement, exact rollback, post-cut retention and fixed inventory. | Windows round-trip/safety/disaster/publication/retirement/history-gap. |
| R-020 | Erasure/reappearance | `PARTIAL` | Monotonic deletion fence + controlled-copy traversal + backup retirement/physical cleanup + pinned tombstones; provider effects external. | All roots/backups/spool/controller copies/tombstones. |
| R-021 | Recursive improvement | `PARTIAL` | Diagnose concrete failed edge; no intelligence score. | Source→revision→later context. |
| R-022 | Disagreement/anticipation | `CHECKED` design | Alternatives + grounds + cheapest distinguishing observation. | Ordinary records after Base. |
| R-023 | Control/status/inbox | `DECIDED` | Daemon public control; supervisor closed privileged effects; status from readback. | Operation/readback paths. |
| R-025 | Interpretation triggers | `DECIDED` | New committed input/correction/question; bookkeeping does not self-trigger. | Inspect enqueue callers. |
| R-026 | Active/pending jobs | `DECIDED` | One active + one coalesced successor; waiting ≠ retry. | Arrival/shutdown modes. |
| R-028–R-045 | Learning/retrieval/history details | `DECIDED` or `PARTIAL` | Recipe bootstrap, attribution, coverage, useful Base, vectors, commitments, source continuity, bounded reads, curation/split/forgetting and typed episode result remain selected. | Implement after Base prerequisites; no new platform. |

## 4. Store, Windows и backup audit

| ID | Объект | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-071–R-081 | Legacy Base/packet/exact-open audit | `CHECKED` selected paths | V2 Memory forwarder/spool/packet/broad-read defects identified; V3 uses one immutable command, real replay, host packet and exact handle/cursor. | Base Slices 1–2. |
| R-082 | SurrealDB Rust SDK | `NOT SELECTED` baseline | SDK/MSRV/license/dependency cost does not fit baseline; bounded remote client selected. | Reconsider only with exact preflight. |
| R-083 | SurrealDB Windows identity | `CHECKED` release identity / `NOT QUALIFIED` runtime | Exact 3.3.4 asset/tag/size/SHA retained. | Download/hash/PE/signature/live Slice 0. |
| R-084–R-100 | Store transport/schema/durability | `CHECKED` design / `NOT IMPLEMENTED` | Query-only authenticated WS, dedicated owner, strict schema, conflicts, no-replace files, root/bootstrap/roles/readiness, sync=every, closed env and explicit DTOs. | Slice 0 live qualification. |
| R-101/R-107 | Backup cut and replay barrier | `CHECKED` design / `NOT IMPLEMENTED` | Brief publication cut, active replay drain, exact typed pages, deletion/spool continuity. | Crash/in-flight/mismatch cases. |
| R-102–R-106 | Endpoint/IPC/launch ownership | `CHECKED` donor/design / `NOT IMPLEMENTED` | Origin not auth; listener+peer owner; mutually attested relay pipe; retained executable/root identity; cancellation-safe socket owner. | Windows implementation. |
| R-108–R-116 | Privileged lifecycle/rollback/ACL/rotation | `CHECKED` design / `NOT IMPLEMENTED` | Inherited supervisor channel, expected-generation selection, exact rollback, controlled roots/backups, session revocation and previous-generation backpressure. | Slice 0 and Base maintenance. |

## 5. Development-system findings

| ID | Объект | Статус | Текущее решение |
|---|---|---|---|
| R-058–R-067 | Delivery collapse / bureaucracy | `CHECKED` | Connected behavior is denominator; one ledger/integrator; cheap preflight; no crate/process/object family per noun; replace superseded authority. |
| R-049 | Verification order | `DECIDED` | Production code first; fmt + minimum changed-package Clippy after coherent increments; broad suite after connected product. |
| R-059 | Append-only authority | `CHECKED` design | Replace stale active text in-place; no errata/report layer. |

## 6. Source coverage added in current passes

| ID | Источник | Статус | Граница вывода |
|---|---|---|---|
| S-056 | Controller `main@613ea6b5`, merged PR #198 and roadmap | `CHECKED` | Current V2 authority; specification only; all L0/L1 unchecked. |
| S-057 | Controller issue #200 + draft PR #201 + CI | `CHECKED` | Fixture fix green; allocator/pointer/schema defect remains. Additional launch/resume/first-observe cases recorded on owner issue. |
| S-058 | Controller issue #199 vs Memory Contract 0.9 | `CHECKED` | `retain_after_seq` required; earliest-row wording insufficient. Owner comment records list/WriteId/credential-output gaps. |
| S-059 | Memory Contract 0.10 | `SUPERSEDED` | Introduced current V2 retention and rollback-safe WriteId baseline; missed admission closure/authority. |
| S-060 | Architecture 11 / Implementation 32 / Cognition 15 | `SUPERSEDED` | Synchronized Contract 0.10 only. |
| S-061 | V2 receipt floor semantics + Contract 0.11 | `CHECKED` design / `SUPERSEDED` mechanism detail | Established absent-old-ID failure, caller/owner erase split and tombstones; treated all admitted in-cut calls as requiring controller row. |
| S-062 | Architecture 12 / Implementation 33 / Cognition 16 | `SUPERSEDED` | Synchronized admission/authority/tombstone boundary before dependency distinction. |
| S-063 | Contract 0.12 dependency analysis | `CHECKED` design / `SUPERSEDED` publication detail | Established controller-closed/dependent split and retained-manifest release fences; did not close manifest publication-unknown race. |
| S-064 | Architecture 13 / Implementation 34 / Cognition 17 / Contract 0.12 | `SUPERSEDED` | Synchronized dependency model before provisional publication fence. |
| S-065 | Controller issue #199 provisional-fence finding + Contract 0.13 | `CHECKED` design / `SUPERSEDED` authority shape | Established rename/sync unknown fence, but selected self-referential final-manifest digest and rollback-local Store row as authority; pinned release only. |
| S-066 | Architecture 14 / Implementation 35 / Cognition 18 / Contract 0.13 | `SUPERSEDED` | Synchronized 0.13 before plan-digest/rollback-safe correction. |
| S-067 | Issue #199 comment 6434757774 + Contract 0.14 | `CHECKED` design / `SUPERSEDED` controlled-set lifecycle | Established plan digest, installation-scoped provisional authority and release+retention pin; omitted crash-safe retirement fact for published backup. |
| S-068 | Architecture 15 / Implementation 36 / Cognition 19 / Contract 0.14 | `SUPERSEDED` | Synchronized publication authority before retirement marker. |
| S-069 | Issue #199 comment 6435002859 + Contract 0.15 | `CHECKED` design | Establishes partial-delete false-pin/false-unpin cases and selects monotonic `retire.json`, distinct from abort and physical cleanup. |
| S-070 | Architecture 16 / Implementation 37 / Cognition 20 / Contract 0.15 + V3 entry point | `CHECKED` design | Current synchronized owner set; runtime not implied. |

Existing source records S-001–S-055 remain historical evidence with their previous exact scope; no donor is qualified wholesale.

## 7. Current queue

| Priority | Работа | Закрывает |
|---|---|---|
| P0 | Controller #200: allocator/schema/API/config/decision fix including cancelled launch/resume and pointer-absent first attach; merge only after validators prove named cases. | R-131, S-057 |
| P0 | Keep issue #199 blocked until controller L0/L1 + #200; implement Contract 0.15 admission/dependency closure, canonical plan, rollback-safe fence/abort/retire reconciliation, release+retention pins, caller cleanup, owner break-glass and tombstones without reviving V1. | R-048, R-126, R-132–R-143 |
| P1 | Memory Slice 0 physical qualification: Windows assets/roots/process/IPC/Surreal/Store/files/WriteId state/backup-plan fences/retirement/rollback/erasure/rotation/shutdown. | R-002, R-006, R-019–R-020, R-071–R-116, R-133, R-141–R-143 |
| P1 | Base Slice 1: event→Store/spool→replay→restart→exact open. | R-001–R-013, R-071–R-107 |
| P1 | Base Slice 2: Claude relay, continuation, lexical retrieval, packet emission, notes/corrections/commitments and maintenance. | R-003–R-045 |
| P1 | Controller V2 L0/L1 implementation under its roadmap. | R-130–R-131 |
| P1 | P1a inference: principal, WriteId state, one mutation owner, admission/dependency classification, canonical plan and installation fence/abort/retire records, calls/copies/runner/read/release+retention fences/tombstones/inventory and one later context consumer. | R-047–R-057, R-117, R-124–R-143 |
| P2 | P1b rotation; embeddings; documents/views/Research/other hosts as independent increments. | R-015–R-018, R-031–R-032 |
| Final | Broad deterministic/live/platform/load suites only after connected product. | R-049 |

## 8. CI state

Memory PR #5325 remains documentation-only. Latest completed known gate failed before MergeCompile:

```text
base-owned workflow oracle       PASS
shared documentation evidence   FAIL: EMPTY_DOCUMENTATION_EVIDENCE
MergeCompile                     SKIPPED
```

It also reported `surrealdb_provisioner = provision_failed`. No fabricated evidence block is accepted. CI failure is not runtime/design proof and does not alter implementation order.

## 9. Последние изменения

| Дата / commit | Изменение |
|---|---|
| 2026-10-26 / `abd2d046` | Architecture 10 / Implementation 31 / Cognition 14 / Contract 0.9 rebased from controller V1 to V2. |
| 2026-10-26 / `ec36adbb` | Contract 0.10: `retain_after_seq`, per-client allocator, stable list window, rollback-safe WriteId generator. |
| 2026-10-26 / `bedfd650`–`520c6e49` | Architecture 11 / Implementation 32 / Cognition 15 synchronized with Contract 0.10. |
| 2026-10-26 / `bb0e08e6`–`60656166` | Contract 0.11 + Architecture 12 / Implementation 33 / Cognition 16: admission closure, caller-vs-owner authority and tombstones. |
| 2026-10-26 / `44b373c4`–`64655bca` | Contract 0.12 + Architecture 13 / Implementation 34 / Cognition 17: controller-closed/dependent split and backup release fences. |
| 2026-10-26 / `510632ac`–`e3c735ea` | Contract 0.13 + Architecture 14 / Implementation 35 / Cognition 18: provisional publication fence, but rollback-local/self-referential authority. |
| 2026-10-27 / `971b30c1`–`7516edb9` | Contract 0.14 + Architecture 15 / Implementation 36 / Cognition 19: canonical plan digest and rollback-safe provisional release+retention pins. |
| 2026-10-27 / `13fa04ef`–current | Contract 0.15 + Architecture 16 / Implementation 37 / Cognition 20: monotonic published-backup retirement marker, distinct from abort and physical cleanup. |
