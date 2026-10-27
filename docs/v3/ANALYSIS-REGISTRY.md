# Eliot V3 — реестр анализа

**Статус на 2026-10-27 · Architecture draft.18 / Implementation draft.39 / Cognition draft.22 / Inference Contract 0.17; controller authority `613ea6b5ff6389c7629a988e271477ee45c9d2c1`; активный рабочий реестр, не runtime gate.**

Это **единственный активный реестр** V3. Он хранит текущее решение, границу доказательства, оставшийся разрыв и следующий connected step. [AUDIT](AUDIT.md) и [AUDIT-MAP](AUDIT-MAP.md) сохраняют доказательства и стабильные dispositions; Git history хранит подробную хронологию.

## 1. Статусы и правила

| Статус | Значение |
|---|---|
| `CHECKED` | Указанный source/design scope прочитан и вывод согласован. Не означает runtime. |
| `DECIDED` | Решение выбрано; код/живой прогон отсутствует. |
| `PARTIAL` | Проверена часть connected edge. |
| `GAP` | В caller→owner→result/unknown→consumer пути отсутствует связь. |
| `OPEN` | Нужно решение или чтение источника. |
| `BLOCKED` | Не реализован predecessor или недоступен источник. |
| `NOT SELECTED` | Механизм не нужен выбранной конструкции. |
| `NOT QUALIFIED` | Артефакт найден, но живой прогон отсутствует. |
| `SUPERSEDED` | Решение заменено текущей authority. |

Правила:

- README, DTO, fixture, receipt, CI или compilation не дают runtime `CHECKED`;
- `IMPLEMENTED` появляется только после real input→operation→durable result/typed unknown→consumer→restart/readback;
- новый механизм не вводится без named caller, owner, result/unknown и consumer;
- controller V1 — donor only;
- Memory inference реализуется только поверх current controller V2;
- один реестр, один current contract, никаких параллельных task/report databases.

## 2. Controller V2 authority и blockers

| ID | Объект | Статус | Текущее решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-123 | Current controller authority | `CHECKED` | `main@613ea6b5`, merged PR #198. V2 = fresh JSON-RPC + SQLite WAL + global external `WriteId`; старый runtime legacy. | Не добавлять Memory в V1. |
| R-130 | Roadmap status | `CHECKED` | `docs/roadmap.md` — sole tracker; L0.1–L1.11 unchecked. | Реализовать foundation после #200. |
| R-131 | Binding allocator/pointer/effect | `CHECKED` design / `BLOCKED` runtime | Issue #200 разделяет per-generation allocator, selected pointer и native effect. Candidate admission pointer не двигает. Launch/resume публикуют target pointer с dispatch/generation transition; first observe/control/detach — после exact effect. `supersedes_revision` = captured selected pointer и может быть NULL при revision>1. Allocator не выводится из pointer/MAX и переживает pruning. PR #201 — fixture-only. | Изменить core/API/config/decisions/schema validator и доказать 18 named cases. |
| R-048 | `inference.text/embed` runtime | `BLOCKED` | V2 methods/runtime отсутствуют; issue #199 blocked on #200 + L0/L1. | Contract 0.17 P1a после foundation. |

## 3. Product и Base

| ID | Объект | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-001 | Product ownership | `CHECKED` design | Host/controller владеет внешней работой; daemon — Memory semantics; supervisor — privileged Store process/candidate/cutover. | Не возвращать Task/provider stack в Memory. |
| R-002 | Process family | `DECIDED` / `NOT IMPLEMENTED` | Supervisor + daemon + active Store + max one disposable candidate; retained identities and finite drain. | Slice 0. |
| R-003 | Continuation address | `DECIDED` | Project/workspace + task or actor/session; path/branch/HEAD = environment. | Fork/two-workspace/late-result. |
| R-004 | Context packet | `CHECKED` design / `NOT IMPLEMENTED` | Exact rendered bytes/digest/revisions/gaps; prepared/emitted/use distinct. | Real host emission/readback. |
| R-005 | Structured correction | `DECIDED` | Observation + history/current revision + result atomically. | Conflict/replay/readback. |
| R-006 | Six Base tables | `CHECKED` design / `NOT IMPLEMENTED` | `stream`, `observation`, `memory`, `memory_history`, `link`, `job`; exact Base fields, string application IDs, fixed DTO queries and migration 0001 selected. | Write assets/query corpus and live-qualify. |
| R-007 | Current/history | `DECIDED` | Exact version handles; no fall-forward/resurrection. | Publication/restart readback. |
| R-008 | Compound grounds | `PARTIAL` | Required groups, alternatives and advisory support separated. | Reducer/cycle/erase/concurrency. |
| R-009 | Retrieval arms | `PARTIAL` | Direct/address/exact/lexical/vector/relation arms independent. | Real plans/limits/noise/exceptions. |
| R-010 | Method consumer | `DECIDED` | Job freezes recipe revision; output must reach later context/open/request. | Before/after product effect. |
| R-011 | Reuse/disclosure | `DECIDED` | Origin, reuse and disclosure independent. | Scoped queries/reduction. |
| R-012 | Claude capture | `CHECKED` design / `NOT IMPLEMENTED` | Finite event profile. | Installed-build qualification. |
| R-013 | Context delivery | `CHECKED` design / `NOT IMPLEMENTED` | Actual content crosses host boundary. | Resume/compact/fork/subagent. |
| R-019 | Backup/restore | `CHECKED` design / `NOT IMPLEMENTED` | Typed backup, exact controller/spool cut, atomic fence-directory visibility, terminal tombstones, daemon lease, supervisor candidate/cutover, exact rollback and fixed post-cut inventory. | Windows round-trip/crash matrix. |
| R-020 | Erasure | `PARTIAL` | Deletion fence + controlled-copy traversal + terminalization/physical cleanup + membership tombstones; provider effects external. | All roots/backups/spool/controller copies. |
| R-021 | Recursive improvement | `PARTIAL` | Diagnose concrete failed edge; no intelligence score. | Source→revision→later context. |
| R-022 | Disagreement | `CHECKED` design | Alternatives + grounds + cheapest distinguishing observation. | Ordinary records after Base. |
| R-023 | Control/status | `DECIDED` | Daemon public control; supervisor closed privileged effects; status from readback. | Operation/readback paths. |
| R-025 | Interpretation triggers | `DECIDED` | New committed input/correction/question only. | Inspect enqueue callers. |
| R-026 | Active/pending jobs | `DECIDED` | One active + one coalesced successor; waiting ≠ retry. | Arrival/shutdown modes. |
| R-028–R-045 | Learning/retrieval/history details | `DECIDED` or `PARTIAL` | Recipe bootstrap, attribution, coverage, vectors, commitments, bounded reads, consolidation/split/forgetting and typed result remain selected. | Implement after Base prerequisites. |

## 4. Store, schema и Windows

| ID | Объект | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-071–R-081 | Legacy Base/packet/open audit | `CHECKED` selected paths | V2 forwarder/spool/packet/broad-read defects identified; V3 uses one immutable command, real replay, host packet and exact cursors. | Base Slices 1–2. |
| R-082 | SurrealDB Rust SDK | `NOT SELECTED` baseline | SDK/MSRV/license/dependency cost does not fit baseline; bounded remote client selected. | Reconsider only with exact preflight. |
| R-083 | SurrealDB Windows identity | `CHECKED` release identity / `NOT QUALIFIED` | Exact 3.3.4 asset/tag/size/SHA retained. | Download/hash/PE/signature/live run. |
| R-084–R-100 | Store transport/durability | `CHECKED` design / `NOT IMPLEMENTED` | Peer-verified query-only WS, dedicated owner, strict schema, conflicts, no-replace files, bootstrap/roles/readiness, `sync=every`, closed env and DTOs. | Slice 0. |
| R-101/R-107 | Backup cut/replay barrier | `CHECKED` design / `NOT IMPLEMENTED` | Brief spool cut, active replay drain, typed pages, deletion/spool continuity. | Crash/in-flight/mismatch. |
| R-102–R-106 | Endpoint/IPC/launch | `CHECKED` donor/design / `NOT IMPLEMENTED` | Origin not auth; listener+peer owner; mutual relay attestation; retained executable/root identity; cancellation-safe socket owner. | Windows implementation. |
| R-108–R-116 | Privileged lifecycle/rollback/ACL/rotation | `CHECKED` design / `NOT IMPLEMENTED` | Inherited supervisor channel, expected-generation selection, exact rollback, controlled roots/backups, session revocation and generation backpressure. | Slice 0. |
| R-150 | Schema bundle authority | `CHECKED` design / `NOT IMPLEMENTED` | SHA-256 over ordered UTF-8/LF assets; digest outside assets; runner binds generation/digest in one fixed transaction; exact params + `INFO FOR DB/TABLE` readback. Unknown partial state fails closed. | Prove bound param/DDL transaction/INFO on exact 3.3.4. |
| R-151 | JSON-safe application/query boundary | `CHECKED` design / `NOT IMPLEMENTED` | Canonical string IDs in explicit fields; native record IDs internal; fixed query projections/DTOs; no `SELECT *`, `type::thing` or generic codec. | Freeze exact grammars and query assets. |
| R-152 | Base lexical index | `CHECKED` design / `NOT IMPLEMENTED` | Analyzer `blank,class` + `lowercase`; separate FULLTEXT indexes on observation excerpt and memory text; lexical score is retrieval only. | Qualify exact 3.3.4 syntax/query/cursor. |
| R-153 | Optional unique keys | `CHECKED` source/design / `NOT IMPLEMENTED` | UNIQUE ignores NONE/NULL; optional address/command/slot keys enforce conditional uniqueness. | Exact expressions/concurrency cases. |

## 5. Inference, backup authority и retention

| ID | Объект | Статус | Текущее решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-047 | One-shot ownership | `CHECKED` design / `NOT IMPLEMENTED` | Memory owns semantic job; controller owns authenticated physical call/copies. | P1a. |
| R-053 | Narrow caller | `DECIDED` / `NOT IMPLEMENTED` | Dedicated `memory_inference`; no owner/Agent/automation/plugin fallback. | Registration/denial matrix. |
| R-117 | Stable caller | `CHECKED` design / `GAP` runtime | Stable client ID owns calls across rotation/rollback. | Old-call read/release after rotation. |
| R-125 | Global WriteId | `DECIDED` / `NOT IMPLEMENTED` | ID + client + method + canonical payload; same-ID live replay. | Receipt/call transaction. |
| R-126 | Minimal durable state | `DECIDED` / `NOT IMPLEMENTED` | Reuse receipts; add client/call rows and private call-owned files only. | Schema/runner. |
| R-128/R-129 | Restore inventory/history gap | `DECIDED` / `NOT IMPLEMENTED` | Fixed `(backup_high_water,inventory_high_water]`; below retain cut = history gap. | Stable list/cursor/cleanup. |
| R-132 | Guaranteed retention | `DECIDED` / `NOT IMPLEMENTED` | Monotonic retain cut constrained by published non-retired backups and unresolved fences; not observed earliest row. | high-water/list/advance. |
| R-133 | External-ID state | `DECIDED` / `NOT IMPLEMENTED` | Atomic monotonic installation file outside rollback roots; advance before job/send. | Windows state-loss/rollback cases. |
| R-134 | Auxiliary mutation identity | `DECIDED` / `NOT IMPLEMENTED` | Cancel/release/retention each has durable pre-send ID and cut state. | Readback/recompute. |
| R-135 | Private credential publication | `DECIDED` / `NOT IMPLEMENTED` | Controller-local owner writes token only to admitted private durable destination. | Install/rotate negatives. |
| R-136 | Admission/auxiliary cut | `CHECKED` design / `NOT IMPLEMENTED` | Drain mutation owner; disposition every call and auxiliary ID before high-water. | Barrier/readback/send denial. |
| R-137 | Cleanup authority | `CHECKED` design / `NOT IMPLEMENTED` | Caller cancel/release; owner-only break-glass; Memory records debt. | Caller/owner cases. |
| R-138 | Membership tombstone | `DECIDED` / `NOT IMPLEMENTED` | Content can erase above cut; bounded membership remains until cut advance. | Inventory/erase cases. |
| R-139 | In-cut dependency fence | `CHECKED` design / `NOT IMPLEMENTED` | Every admitted call closed/dependent; dependent copies stay unreleased while pinned. | Pre-release recheck/restore. |
| R-141 | Canonical plan digest | `CHECKED` design / `NOT IMPLEMENTED` | Digest excludes itself, publication state and later parts/manifest. | Codec/mismatch cases. |
| R-144 | Self-contained terminal tombstones | `CHECKED` design / `NOT IMPLEMENTED` | Abort/retire remain terminal after cleanup; malformed/both/mismatch fail closed. | Codecs/prerequisites/restart. |
| R-147 | Concrete process owner/lock order | `CHECKED` design / `NOT IMPLEMENTED` | Daemon owns mutation + backup-set owners; supervisor owns candidate/cutover. New fence closes mutation, publishes final fence, then reopens. | Owner task/channel/crash cases. |
| R-148 | Atomic final backup-directory publication | `CHECKED` design / `NOT IMPLEMENTED` | `b_<32hex>`; temp directory with fence → flush → no-replace rename → parent flush/readback. Pre-rename temp non-pinning; post-rename unknown pins. | Windows directory-rename/collision matrix. |
| R-149 | Restore lease enforcement | `CHECKED` design / `NOT IMPLEMENTED` | Daemon retains no-follow directory/fence/manifest/part handles with delete sharing denied through final recheck. Daemon/channel loss forces candidate discard. | Forced crash/delete-race cases. |

## 6. Development-system findings

| ID | Объект | Статус | Решение |
|---|---|---|---|
| R-058–R-067 | Delivery collapse/bureaucracy | `CHECKED` | Connected behavior is denominator; one ledger/integrator; cheap preflight; no object family per noun; replace superseded authority. |
| R-049 | Verification order | `DECIDED` | Production code first; fmt + minimum changed-package Clippy after coherent increments; broad suites after connected product. |
| R-059 | Append-only authority | `CHECKED` | Replace stale active text; no errata/report layer. |

## 7. Normative synchronization

| ID | Объект | Статус | Решение |
|---|---|---|---|
| R-024 | Normative synchronization | `CHECKED` design | Architecture 18 / Implementation 39 / Cognition 22 / Contract 0.17 / V3 README agree on concrete backup owner, atomic first visibility, lease/candidate crash custody, schema bundle, IDs, query DTOs and lexical indexes. |
| R-076 | Base/Store synchronization | `CHECKED` design / `NOT IMPLEMENTED` | Host/capture/Store/Windows/schema/backup baseline synchronized and independent of inference availability. |

## 8. Source coverage added in current passes

| ID | Источник | Статус | Граница вывода |
|---|---|---|---|
| S-056 | Controller `main@613ea6b5`, PR #198, roadmap | `CHECKED` | V2 authority; specification only; L0/L1 unchecked. |
| S-057/S-073 | Controller issue #200, PR #201, core/API/config/schema validator | `CHECKED` | Current issue body owns allocator/pointer/effect separation and 18 acceptance cases; PR #201 fixture-only. |
| S-058 | Controller issue #199 | `CHECKED` | Current cross-repository inference owner; blocked. |
| S-059–S-070 | Contracts 0.10–0.15 and owner sets | `SUPERSEDED` details | Historical stages established retention, IDs, cut, dependency, plan and retirement. |
| S-071/S-072 | Contract 0.16 and owner set | `SUPERSEDED` physical-owner detail | Established self-contained terminals and abstract owner/lease; omitted concrete process owner and atomic first directory visibility. |
| S-074 | Issue #199 comment `6437047065` | `CHECKED` | Selects daemon owner, lock order, supervisor candidate custody, crash discard and staged-directory publication. |
| S-075 | Official SurrealDB DEFINE INDEX/ANALYZER/PARAM/INFO docs | `CHECKED` public source / `NOT QUALIFIED` runtime | Syntax and NONE/NULL unique behavior; exact 3.3.4 live proof remains Slice 0. |
| S-076 | V2 migration/schema donors | `CHECKED` selected paths / `NOT SELECTED` wholesale | Useful checksum/schema patterns; not V3 authority. |
| S-077 | Architecture 18 / Implementation 39 / Cognition 22 / Contract 0.17 + entrypoints | `CHECKED` design | Current synchronized owner set; runtime not implied. |

Existing S-001–S-055 remain historical evidence with their recorded exact scope; no donor is qualified wholesale.

## 9. Current queue

| Priority | Работа | Закрывает |
|---|---|---|
| P0 | Controller #200 implementation and validator acceptance. | R-131 |
| P0 | Keep issue #199 blocked until #200 + V2 L0/L1; never revive V1. | R-048, R-123, R-130 |
| P1 | Write migration 0001/query assets exactly as Implementation 39, then live-qualify 3.3.4 behavior. | R-006, R-150–R-153 |
| P1 | Slice 0 Windows/process/IPC/Store/schema/files/external-ID/backup-owner/terminal/lease/rollback/rotation/shutdown. | R-002, R-019–R-020, R-083–R-116, R-133, R-141, R-144, R-147–R-153 |
| P1 | Base Slice 1: event→Store/spool→replay→restart→exact open. | R-001–R-013, R-071–R-107 |
| P1 | Base Slice 2: Claude relay, continuation, lexical retrieval, packet emission, notes/corrections/commitments and maintenance. | R-003–R-045 |
| P1 | Controller V2 L0/L1. | R-130–R-131 |
| P1 | Inference P1a after foundation. | R-047–R-057, R-117, R-125–R-149 |
| P2 | Rotation, embeddings, documents/views/Research/other hosts. | R-015–R-018, R-031–R-032 |
| Final | Broad deterministic/live/platform/load suites after connected product. | R-049 |

## 10. CI state

PR #5325 remains documentation-only. Latest completed known gate failed before MergeCompile:

```text
base-owned workflow oracle       PASS
shared documentation evidence   FAIL: EMPTY_DOCUMENTATION_EVIDENCE
MergeCompile                     SKIPPED
```

It also reported `surrealdb_provisioner = provision_failed`. No fabricated evidence block is accepted. CI status is not design/runtime proof.

## 11. Последний проход

| Дата / baseline | Изменение |
|---|---|
| 2026-10-27 / `7a18948d` | Contract 0.16: self-contained terminals, abstract backup owner/lease and auxiliary cut. |
| 2026-10-27 / `a08cbf1b` | Registry exposed concrete owner, atomic directory and schema-authority gaps. |
| 2026-10-27 / current synchronized set | Architecture 18 / Implementation 39 / Cognition 22 / Contract 0.17: daemon backup owner, staged final fence visibility, candidate crash custody, migration 0001 and fixed query boundary. |