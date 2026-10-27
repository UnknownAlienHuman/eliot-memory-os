# Eliot V3 — реестр анализа

**Статус на 2026-10-27 · опубликованная нормативная база Architecture draft.17 / Implementation draft.38 / Cognition draft.21 / Inference Contract 0.16; новые R-147–R-150 ещё требуют синхронизации owner-docs; controller authority `613ea6b5ff6389c7629a988e271477ee45c9d2c1`; активный рабочий реестр, не runtime gate.**

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
| R-131 | Binding allocator, pointer и effect boundary | `CHECKED` design / `BLOCKED` runtime | Issue #200 теперь разделяет monotonic per-generation allocation, selected current pointer и native effect. Candidate admission не двигает pointer. Launch/resume публикуют target pointer только атомарно с dispatch/generation transition; pre-dispatch cancel оставляет pointer absent. First observe создаёт pointer после exact attach; control/detach двигают его после exact effect. `supersedes_revision` означает captured selected pointer и может быть `NULL` при revision > 1. Allocator нельзя восстанавливать из pointer/MAX и нельзя снижать при pruning. PR #201 исправляет только fixtures. | Изменить core/API/config/decisions/schema validator и доказать 18 acceptance cases issue #200 до L0/L1. |
| R-048 | `inference.text/embed` runtime | `BLOCKED` | Current V2 methods/runtime absent; issue #199 blocked on #200 + L0/L1. | Реализовать current Contract только после foundation. |

### 2.2 Memory inference contract

| ID | Объект | Статус | Текущее решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-047 | One-shot ownership | `CHECKED` design / `NOT IMPLEMENTED` | Memory owns semantic job/source/recipe/decode/publication; controller owns authenticated physical call/readback/copies. | P1a after V2 foundation. |
| R-053 | Narrow caller | `DECIDED` / `NOT IMPLEMENTED` | Dedicated `memory_inference`; no owner, Agent, automation, plugin or no-token fallback. | Registration + denial matrix. |
| R-117 | Stable caller continuity | `CHECKED` design / `GAP` runtime | Stable `client_id = memory:<random-installation-id>` owns calls across token rotation and Memory rollback. | Pre/post-rotation old-call read/release. |
| R-125 | Global `WriteId` call identity | `DECIDED` / `NOT IMPLEMENTED` | Live call identity = global ULID + exact client + method + canonical payload; call ID equals WriteId. | Receipt/call transaction. |
| R-126 | Minimal V2 durable state | `DECIDED` / `NOT IMPLEMENTED` | Reuse `write_receipts`; add only `memory_inference_clients`, `inference_calls` and private call-owned files. | Schema/runner/copy lifecycle. |
| R-132 | Guaranteed post-cut retention | `DECIDED` / `NOT IMPLEMENTED` | Monotonic `retain_after_seq` protects complete post-cut membership above minimum high-water of published non-retired backups and unresolved provisional fences. It is not observed earliest row and is not lowered for in-cut dependencies. | Implement high-water/list/retention.advance and controlled-set scan. |
| R-133 | Memory external WriteId generator | `DECIDED` / `NOT IMPLEMENTED` | One locked atomic installation-scoped monotonic ULID state outside rollback roots. Advance before job record/send and at least daemon floor/current monotonic time. | Implement Windows durable state, identity mismatch, lost-state and rollback cases. |
| R-134 | Auxiliary mutation identity | `DECIDED` / `NOT IMPLEMENTED` | Cancel, release and retention advance each get durable pre-send caller WriteId. | Add fields/readback path; no generic receipt-query API or new table. |
| R-135 | Private credential publication | `DECIDED` / `NOT IMPLEMENTED` | Controller-local owner publishes derived token only to admitted create-new/no-reparse private destination with ACL + file/parent durability. | Qualify install/reissue/lost-reply/path negatives. |
| R-128 | Restore external-work inventory | `DECIDED` / `NOT IMPLEMENTED` | Backup stores high-water + retain cut; restore captures fixed `(backup_high_water, inventory_high_water]` membership and dispositions every out-of-target call. | Stable cursor/list + cleanup jobs. |
| R-129 | Retention gap | `DECIDED` / `NOT IMPLEMENTED` | `backup_high_water < retain_after_seq` means `history_gap`; physical row presence is diagnostic only. | Implement and qualify. |
| R-136 | Backup admission closure | `CHECKED` design / `NOT IMPLEMENTED` | Before high-water, one controller-mutation owner is closed/drained. Call IDs and auxiliary IDs receive exact cut dispositions; release/retention cannot race controlled-set changes. | Implement barrier/readback, retired-ID send denial and mutation serialization. |
| R-137 | Cleanup/erase authority | `CHECKED` design / `NOT IMPLEMENTED` | Valid caller uses optional cancel + `release(abandon_for_erasure)`. `inference.erase` is controller-owner-only break-glass; Memory records `owner_action_required` and later owner readback, never owner WriteId/effect. | Implement caller path, owner-action debt and denial tests. |
| R-138 | Retention tombstone vs physical erasure | `DECIDED` / `NOT IMPLEMENTED` | Content/sensitive facts erase immediately, but calls above retain cut keep bounded text-free membership tombstone. Tombstone deletion requires terminalization of pinning backups and prior cut advance. | Add erased/abandoned tombstone state and inventory cases. |
| R-139 | In-cut backup dependency release fence | `CHECKED` design / `NOT IMPLEMENTED` | Every admitted in-cut job is `controller_closed` or `controller_dependent`. Dependent calls/copies stay unreleased while any restorable/provisional backup needs them. | Implement controlled-set dependency scan, pre-release recheck and restore/release cases. |
| R-140 | Contract 0.13 provisional fence | `SUPERSEDED` by R-141/R-142 | Final-manifest digest in rollback-local Store job created self-reference and rollback authority loss. | Do not implement 0.13 shape. |
| R-141 | Canonical backup plan digest | `CHECKED` design / `NOT IMPLEMENTED` | Precommit `backup_plan_digest` over explicit immutable plan fields excluding digest itself, publication state and later part/manifest digests. Final manifest repeats plan digest plus actual inventories. | Implement canonical plan codec, digest/readback and mismatch cases. |
| R-142 | Rollback-safe provisional authority | `CHECKED` principle / `PARTIAL` physical publication | Installation-scoped fence before parts remains selected; ambiguity pins release/retention. Contract 0.16 leaves an empty-final-directory crash window between directory creation and `fence.json`. | Replace with R-148 staged-directory publication. |
| R-143 | Monotonic published-backup retirement | `CHECKED` principle / `SUPERSEDED` terminal-shape detail | Published backup leaves restorable set through durable retire marker, distinct from abort/erase. | Use R-144 current terminal semantics. |
| R-144 | Self-contained terminal backup tombstones | `CHECKED` design / `NOT IMPLEMENTED` | `abort.json`/`retire.json` bind backup/plan/fence identity and deterministic operation; retire also binds manifest digest. After prerequisites/readback they remain terminal after content cleanup. Both/malformed/contradictory records fail closed. | Implement codecs, prerequisite checks, standalone restart scan and cleanup cases. |
| R-145 | Backup-set owner, ID and restore lease | `CHECKED` principle / `PARTIAL` process owner | One owner/lease is required, but Contract 0.16 did not assign it to daemon or supervisor. That left controller-release serialization and candidate-custody crash behavior physically unowned. | Apply R-147/R-149 and synchronize owner docs. |
| R-146 | Auxiliary cut and rollback mirror fence | `CHECKED` design / `NOT IMPLEMENTED` | Every cancel/release/retention ID is `effect_observed|retired_not_sent|mutation_unknown`. Old backup never first-admits absent auxiliary ID. Current effects are recomputed after inventory; restored Store mirrors are status-only and cannot mutate installation state or clear pins. | Implement fields, startup reconciliation, stale-mirror supersession and fresh-ID recomputation. |
| R-147 | Concrete backup-set process owner and lock order | `DECIDED` / `NOT IMPLEMENTED` | Daemon owns backup-set owner, installation-record transitions, restore leases and physical cleanup because it also owns controller-mutation serialization and public backup control. Supervisor owns disposable candidate process/root and final cutover. New fence order: close+drain mutation owner → publish/read back fence under backup-set owner → reopen mutation admission. Terminal transitions only remove pins, so stale pre-terminal reads are conservative. | Update Architecture/Implementation/Cognition/Contract; add typed lease/candidate-discard frames and deadlock/crash cases. |
| R-148 | Atomic final backup-directory publication | `DECIDED` / `NOT IMPLEMENTED` | Canonical ID is `b_` + 32 lowercase hex chars from 128 OS-random bits. Build `fence.json` in a same-parent private temp directory, flush file+directory, no-replace rename directory to final ID, flush parent and exact readback. Pre-rename temp is non-restorable/non-pinning cleanup debt; post-rename sync/readback failure is publication unknown and pins after reconciliation. No empty final directory or reservation service. | Synchronize Contract and qualify directory rename/collision/temp cleanup/post-rename unknown on Windows. |
| R-149 | Restore lease physical enforcement | `DECIDED` / `NOT IMPLEMENTED` | Daemon lease retains no-follow directory/fence/manifest/part handles with delete sharing denied and holds final terminal-state recheck through cutover decision. Daemon/channel loss makes supervisor kill/reap/discard candidate before another daemon or cutover; supervisor loss is contained by Job. | Add inherited-channel protocol and forced crash matrix. |

### 2.3 Store schema/migration authority

| ID | Объект | Статус | Текущее решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-006 | Six Memory tables and migration 0001 | `CHECKED` conceptual model / `GAP` executable contract | Six primary tables are selected, but exact field types, canonical string IDs, analyzer/index definitions, schema metadata wrapper and fixed query DTOs are not yet written. Implementation cannot begin from names alone. | Specify 0001 schema bundle and query corpus before Slice 0 code. |
| R-150 | Non-self-referential schema bundle authority | `DECIDED` / `NOT IMPLEMENTED` | Do not embed a migration file's own digest literal inside the bytes being hashed. Compute SHA-256 over exact ordered UTF-8/LF migration assets; runner supplies resulting bundle digest as a bound value in a fixed transactional metadata wrapper. Persist `$eliot_schema_generation` and `$eliot_schema_bundle_sha256`, then compare exact pinned-version `INFO FOR DB/TABLE` definitions. Unknown outcome: exact committed readback, exact empty retry, otherwise fail closed/discard fresh candidate. | Verify bound value in `DEFINE PARAM`, DDL transaction/rollback and INFO normalization on exact 3.3.4. |
| R-151 | JSON-safe application identity and query boundary | `DECIDED` / `NOT IMPLEMENTED` | Wire/application identities are bounded canonical strings in explicit fields; Surreal native record IDs stay internal because JSON cannot round-trip Thing/UUID/datetime/decimal safely. Fixed queries select by indexed string identity and explicit projection; no `SELECT *`, `type::thing` or generic Value codec. | Freeze ID grammar, field types, DTOs and exact-open/query continuations. |
| R-152 | Base lexical index | `DECIDED` / `NOT IMPLEMENTED` | Migration 0001 must define a multilingual-neutral analyzer (`blank,class` + `lowercase`) and separate FULLTEXT indexes for `observation.search_excerpt` and `memory.search_text`; exact/unique indexes remain separate kinds. Lexical query uses fixed `@@` projection/order/limit and does not become semantic truth. | Confirm exact 3.3.4 analyzer/index syntax and ranking/cursor query. |
| R-153 | Optional unique keys | `CHECKED` source / `NOT IMPLEMENTED` | Surreal unique indexes ignore `NONE`/`NULL`; derived `address_unique_key` and active/pending job slot can therefore enforce conditional uniqueness without blocking unaddressed/terminal rows. | Add exact VALUE expressions and concurrency cases to 0001. |

### 2.4 Normative synchronization

| ID | Объект | Статус | Текущее решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-024 | Normative synchronization | `PARTIAL` | Published Architecture 17 / Implementation 38 / Cognition 21 / Contract 0.16 agree with each other, but do not yet contain selected R-147–R-153 corrections. Registry and controller issues are ahead of owner docs. | Publish one synchronized next revision; do not report design set as fully current before then. |
| R-076 | Base/Store synchronization | `PARTIAL` design / `NOT IMPLEMENTED` | Existing Host/Store/Windows baseline remains coherent, but exact migration/query contract and backup-owner publication boundary are still open. | Close R-147–R-153, then return CHECKED. |

## 3. Product, Base и memory semantics

| ID | Объект | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-001 | Product ownership | `CHECKED` design | Host/controller external work; Memory daemon semantics/state; supervisor privileged process/candidate/cutover effects. | Не возвращать Task/provider stack в Memory. |
| R-002 | Process family / idle drain | `DECIDED` / `NOT IMPLEMENTED` | Supervisor + daemon + active Store + max one candidate; retained identities; finite drain. | Slice 0 process/IPC/shutdown. |
| R-003 | Continuation address | `DECIDED` | Project/workspace + task or actor/session; path/branch/HEAD are environment. | Fork/two-workspace/late-result cases. |
| R-004 | Context packet identity | `CHECKED` design / `NOT IMPLEMENTED` | Rendered bytes/digest + exact revisions + gaps in ordinary data. | Real host emission/readback. |
| R-005 | Structured correction | `DECIDED` | Correction observation + revision/history + saved result atomically. | Conflict/replay/readback. |
| R-007 | Current/history | `DECIDED` | Exact version handles; no fall-forward or predecessor resurrection. | Publication/restart readback. |
| R-008 | Compound grounds | `PARTIAL` | Required groups, alternatives and advisory support separated. | Reducer/cycle/erase/concurrency. |
| R-009 | Retrieval arms / packing | `PARTIAL` | Exact/address/lexical/vector/relation arms independent. | Real plans/limits/noise/exceptions. |
| R-010 | Processing-method consumer | `DECIDED` | Job freezes recipe revision; later consumer must read result. | Changed later context. |
| R-011 | Reuse/disclosure | `DECIDED` | Origin, reuse scope and disclosure independent. | Scoped queries/reduction. |
| R-012 | Native hook capture | `CHECKED` design / `NOT IMPLEMENTED` | Finite Claude event profile. | Installed-build qualification. |
| R-013 | Native context delivery | `CHECKED` design / `NOT IMPLEMENTED` | Actual packet crosses host boundary; prepared/emitted/use distinct. | Resume/compact/fork/subagent. |
| R-019 | Backup/restore | `PARTIAL` design / `NOT IMPLEMENTED` | Typed backup, brief cut, call+auxiliary closure, plan, terminal authority, exact rollback and inventory are selected; physical owner and final-directory publication await owner-doc sync. | Publish R-147–R-149 and run Windows round-trip later. |
| R-020 | Erasure/reappearance | `PARTIAL` | Monotonic deletion fence + controlled-copy traversal + terminalization/physical cleanup + pinned tombstones; provider effects external. | All roots/backups/spool/controller copies/tombstones. |
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
| R-084–R-100 | Store transport/schema/durability | `CHECKED` design / `NOT IMPLEMENTED` | Query-only authenticated WS, dedicated owner, strict schema, conflicts, no-replace files, root/bootstrap/roles/readiness, sync=every, closed env and explicit DTOs. | Slice 0 live qualification plus R-150–R-153. |
| R-101/R-107 | Backup cut and replay barrier | `CHECKED` design / `NOT IMPLEMENTED` | Brief publication cut, active replay drain, exact typed pages, deletion/spool continuity. | Crash/in-flight/mismatch cases. |
| R-102–R-106 | Endpoint/IPC/launch ownership | `CHECKED` donor/design / `NOT IMPLEMENTED` | Origin not auth; listener+peer owner; mutually attested relay pipe; retained executable/root identity; cancellation-safe socket owner. | Windows implementation. |
| R-108–R-116 | Privileged lifecycle/rollback/ACL/rotation | `CHECKED` design / `NOT IMPLEMENTED` | Inherited supervisor channel, expected-generation selection, exact rollback, controlled roots/backups, session revocation and previous-generation backpressure. | Add daemon-owned backup lease/candidate-discard protocol, then Slice 0. |

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
| S-057 | Controller issue #200 + draft PR #201 + exact core/API/config/schema validator | `CHECKED` | Issue body now owns allocator/pointer/effect separation, nullable selected predecessor, allocator retention and 18 acceptance cases. PR #201 remains fixture-only. |
| S-058 | Controller issue #199 vs Memory inference contracts | `CHECKED` | Current cross-repository owner issue; implementation remains blocked. |
| S-059–S-070 | Contracts 0.10–0.15 and synchronized owner sets | `SUPERSEDED` mechanism details | Historical stages established retention, WriteId, admission closure, dependency split, plan digest and terminal retirement; current authority is 0.16 plus new findings below. |
| S-071 | Issue #199 comment 6435580371 + Contract 0.16 | `CHECKED` design / `SUPERSEDED` owner/publication detail | Established self-contained terminals, random IDs, abstract backup-set owner/restore lease and auxiliary cut; did not assign process owner or close pre-fence directory window. |
| S-072 | Architecture 17 / Implementation 38 / Cognition 21 / Contract 0.16 + V3 navigation | `CHECKED` published set / `PARTIAL` current design | Published files agree with each other but precede R-147–R-153. |
| S-073 | Controller issue #200 body updated 2026-10-27 | `CHECKED` design | Exact selected allocator, pointer publication, supersedes semantics, retention and acceptance matrix. |
| S-074 | Controller issue #199 comment 6437047065 | `CHECKED` design | Selects daemon backup-set owner, mutation-owner lock order, supervisor candidate custody, crash discard and staged-directory fence publication. |
| S-075 | SurrealDB official 3.x DEFINE INDEX/PARAM/INFO docs | `CHECKED` public source / `NOT QUALIFIED` runtime | UNIQUE ignores NONE/NULL; FULLTEXT and analyzer syntax; OVERWRITE params and INFO catalog are available. Exact 3.3.4 live behavior remains Slice 0 qualification. |
| S-076 | V2 migration runner and Surreal adapter schema donors | `CHECKED` selected paths / `NOT SELECTED` wholesale | Donors show checksum and schema patterns but not the V3 fixed DTO/query/migration authority. |

Existing source records S-001–S-055 remain historical evidence with their previous exact scope; no donor is qualified wholesale.

## 7. Current queue

| Priority | Работа | Закрывает |
|---|---|---|
| P0 | Synchronize Architecture/Implementation/Cognition/Contract/README with R-147–R-153; return R-024/R-076 to CHECKED only after exact readback. | R-024, R-076, R-142, R-145, R-147–R-153 |
| P0 | Controller #200: implement allocator/schema/API/config/decision correction and merge only after named acceptance cases. | R-131, S-057, S-073 |
| P0 | Keep issue #199 blocked until controller L0/L1 + #200; implement next synchronized contract without reviving V1. | R-048, R-126, R-132–R-149 |
| P1 | Specify migration 0001: exact IDs/types/analyzer/indexes/schema bundle metadata and fixed query DTO corpus. | R-006, R-150–R-153 |
| P1 | Memory Slice 0 physical qualification: Windows assets/roots/process/IPC/Surreal/Store/files/WriteId state/backup-set owner/terminal records/restore lease/rollback/erasure/rotation/shutdown. | R-002, R-006, R-019–R-020, R-071–R-116, R-133, R-141–R-153 |
| P1 | Base Slice 1: event→Store/spool→replay→restart→exact open. | R-001–R-013, R-071–R-107 |
| P1 | Base Slice 2: Claude relay, continuation, lexical retrieval, packet emission, notes/corrections/commitments and maintenance. | R-003–R-045 |
| P1 | Controller V2 L0/L1 implementation under its roadmap. | R-130–R-131 |
| P1 | P1a inference after foundation: principal, WriteId state, mutation owner, daemon backup-set owner, call+auxiliary cut, staged fence/terminal records, restore lease, calls/copies/runner/release+retention/tombstones/inventory and later context consumer. | R-047–R-057, R-117, R-124–R-149 |
| P2 | P1b rotation; embeddings; documents/views/Research/other hosts as independent increments. | R-015–R-018, R-031–R-032 |
| Final | Broad deterministic/live/platform/load suites only after connected product. | R-049 |

## 8. CI state

Memory PR #5325 remains documentation-only. Latest completed gate failed before MergeCompile:

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
| 2026-10-26 / `ec36adbb`–`520c6e49` | Contract 0.10 and owner docs: retention, stable inventory and rollback-safe WriteId baseline. |
| 2026-10-26 / `bb0e08e6`–`64655bca` | Contracts 0.11–0.12 and owner docs: admission/authority/tombstones and closed/dependent split. |
| 2026-10-26 / `510632ac`–`7516edb9` | Contracts 0.13–0.14 and owner docs: provisional fence corrected to canonical plan and rollback-safe pins. |
| 2026-10-27 / `13fa04ef`–`8d58c5e1` | Contract 0.15 + owner docs: retire marker distinct from abort/physical cleanup. |
| 2026-10-27 / `2df00a69`–`7a18948d` | Contract 0.16 + Architecture 17 / Implementation 38 / Cognition 21: self-contained terminals, abstract backup-set owner, restore lease and auxiliary cut. |
| 2026-10-27 / issue updates + current registry commit | Issue #200 corrected to allocator/pointer/effect model; issue #199 records daemon owner and staged-directory publication; R-147–R-153 queued for synchronized next revision. |
