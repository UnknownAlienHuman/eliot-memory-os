# Eliot V3 — реестр анализа

**Статус на 2026-10-27 · Architecture draft.19 / Implementation draft.42 / Cognition draft.23 / Inference Contract 0.18; controller authority `613ea6b5ff6389c7629a988e271477ee45c9d2c1`; активный рабочий реестр, не runtime gate.**

Это **единственный активный реестр** V3. Он хранит текущее решение, границу доказательства, оставшийся разрыв и следующий connected step. [AUDIT](AUDIT.md) и [AUDIT-MAP](AUDIT-MAP.md) сохраняют доказательства и stable dispositions; Git history хранит хронологию.

## 1. Статусы и правила

| Статус | Значение |
|---|---|
| `CHECKED` | Source/design scope прочитан и вывод согласован; runtime не следует. |
| `DECIDED` | Решение выбрано; код/живой прогон отсутствует. |
| `PARTIAL` | Проверена часть connected edge. |
| `GAP` | В caller→owner→result/unknown→consumer пути отсутствует связь. |
| `OPEN` | Нужно решение или чтение источника. |
| `BLOCKED` | Не реализован predecessor или недоступен источник. |
| `NOT SELECTED` | Механизм не нужен выбранной конструкции. |
| `NOT QUALIFIED` | Артефакт найден, но живой прогон отсутствует. |
| `SUPERSEDED` | Решение заменено current authority. |

Правила:

- README, DTO, fixture, receipt, upstream test, CI или compilation не дают runtime `CHECKED`;
- `IMPLEMENTED` появляется только после real input→operation→durable result/typed unknown→consumer→restart/readback;
- новый механизм требует named caller, owner, result/unknown и consumer;
- controller V1 — donor only; Memory inference только поверх current controller V2;
- один registry и один current inference contract; никаких параллельных reports/task databases;
- exact-tag source evidence и live qualification всегда разделены.

## 2. Controller V2 authority и blockers

| ID | Объект | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-123 | Current controller authority | `CHECKED` | `main@613ea6b5`, merged PR #198. V2 = fresh JSON-RPC + SQLite WAL + global external `WriteId`; старый runtime legacy. | Не добавлять Memory в V1. |
| R-130 | Roadmap status | `CHECKED` | `docs/roadmap.md` — sole tracker; L0.1–L1.11 unchecked. | Реализовать foundation после #200. |
| R-131 | Binding allocator/pointer/effect | `CHECKED` design / `BLOCKED` runtime | Issue #200 разделяет per-generation allocator, selected pointer и native effect. Candidate admission pointer не двигает. Launch/resume публикуют target pointer с dispatch; attach/detach — после exact effect. Allocator не выводится из pointer/MAX и переживает pruning. PR #201 fixture-only. | Изменить core/API/config/decisions/schema validator и доказать named cases. |
| R-048 | `inference.text/embed` runtime | `BLOCKED` | V2 methods/runtime отсутствуют; issue #199 blocked on #200 + L0/L1. | Contract 0.18 P1a после foundation. |

## 3. Product и Base

| ID | Объект | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-001 | Product ownership | `CHECKED` design | Host/controller external work; daemon Memory semantics; supervisor privileged Store process/candidate/cutover. | Не возвращать Task/provider stack в Memory. |
| R-002 | Process family | `DECIDED` / `NOT IMPLEMENTED` | Supervisor + daemon + active Store + max one disposable candidate; retained identities and finite drain. | Slice 0. |
| R-003 | Continuation address | `DECIDED` | Project/workspace + task or actor/session; path/branch/HEAD = environment. | Fork/two-workspace/late-result. |
| R-004 | Context packet | `CHECKED` design / `NOT IMPLEMENTED` | Exact rendered bytes/digest/revisions/gaps; prepared/emitted/use distinct. | Real host emission/readback. |
| R-005 | Structured correction | `DECIDED` | Observation + history/current revision + result atomically. | Conflict/replay/readback. |
| R-006 | Six Base tables | `CHECKED` design / `NOT IMPLEMENTED` | `stream`, `observation`, `memory`, `memory_history`, `link`, `job`; canonical IDs, immutable fields, row assertions, reader-backed indexes, fixed DTO queries and migration 0001. | Write assets/query corpus and live-qualify. |
| R-007 | Current/history | `DECIDED` | Exact version handles; no fall-forward/resurrection. | Publication/restart readback. |
| R-008 | Compound grounds | `PARTIAL` | Required groups, alternatives and advisory support separated. | Reducer/cycle/erase/concurrency. |
| R-009 | Retrieval arms | `CHECKED` design / `NOT IMPLEMENTED` | Direct/address/exact/lexical/vector/relation arms independent. Lexical = bounded snapshot, not fake durable cursor. | Real plans/limits/noise/exceptions. |
| R-010 | Method consumer | `DECIDED` | Job freezes recipe revision; output must reach later context/open/request. | Before/after product effect. |
| R-011 | Reuse/disclosure | `DECIDED` | Origin, reuse and disclosure independent. | Scoped queries/reduction. |
| R-012 | Claude capture | `CHECKED` design / `NOT IMPLEMENTED` | Finite event profile. | Installed-build qualification. |
| R-013 | Context delivery | `CHECKED` design / `NOT IMPLEMENTED` | Actual content crosses host boundary. | Resume/compact/fork/subagent. |
| R-019 | Backup/restore | `CHECKED` design / `NOT IMPLEMENTED` | Typed backup, exact cut, atomic fence first visibility, terminal tombstones, bounded daemon lease, supervisor candidate/cutover, exact rollback and fixed inventory. | Windows round-trip/crash/load matrix. |
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
| R-071–R-081 | Legacy Base/packet/open audit | `CHECKED` selected paths | V2 forwarder/spool/packet/broad-read defects identified; V3 uses immutable command, replay, actual packet and exact cursors. | Base Slices 1–2. |
| R-082 | SurrealDB Rust SDK | `NOT SELECTED` baseline | SDK/MSRV/license/dependency cost does not fit baseline; bounded remote client selected. | Reconsider only with exact preflight. |
| R-083 | SurrealDB Windows identity | `CHECKED` release identity / `NOT QUALIFIED` | Exact 3.3.4 asset/tag/size/SHA retained. | Download/hash/PE/signature/live run. |
| R-084–R-100 | Store transport/durability | `CHECKED` design / `NOT IMPLEMENTED` | Peer-verified query-only WS, dedicated owner, strict schema, conflicts, no-replace files, bootstrap/roles/readiness, `sync=every`, closed env and DTOs. | Slice 0. |
| R-101/R-107 | Backup cut/replay barrier | `CHECKED` design / `NOT IMPLEMENTED` | Brief spool cut, active replay drain, typed pages, deletion/spool continuity. | Crash/in-flight/mismatch. |
| R-102–R-106 | Endpoint/IPC/launch | `CHECKED` donor/design / `NOT IMPLEMENTED` | Origin not auth; listener+peer owner; mutual relay attestation; retained executable/root identity; cancellation-safe socket owner. | Windows implementation. |
| R-108–R-116 | Privileged lifecycle/rollback/ACL/rotation | `CHECKED` design / `NOT IMPLEMENTED` | Inherited supervisor channel, expected-generation selection, exact rollback, controlled roots/backups, session revocation and generation backpressure. | Slice 0. |
| R-150 | Schema bundle authority | `CHECKED` design / `PARTIAL` source / `NOT IMPLEMENTED` | Bundle preimage includes format, runner protocol, wrapper, ordered DDL and expected catalog. PARAM rollback and cancelled index overwrite are exact-tag evidence; complete wrapper, bound metadata and all DDL rollback remain unqualified. | Execute exact wrapper/failure/readback matrix on 3.3.4. |
| R-151 | JSON-safe application/query boundary | `CHECKED` design / `NOT IMPLEMENTED` | Canonical string IDs; native record IDs internal; fixed projections/DTOs; no generic codec. | Freeze exact grammar/query assets. |
| R-152 | Base lexical indexes | `CHECKED` source/design / `NOT IMPLEMENTED` | Exact analyzer/FULLTEXT syntax and representative index iteration confirmed. | Write assets; measure write cost and reader plans. |
| R-153 | Optional unique keys | `CHECKED` exact source/design / `NOT IMPLEMENTED` | 3.3.4 UNIQUE skips a tuple containing either NONE or NULL. V3 writes only NONE for “not applicable”; NULL is forbidden in conditional-key fields. | Concurrent insert/conflict through production client. |
| R-154 | Numbered FTS score query | `CHECKED` exact tests/design / `NOT IMPLEMENTED` | `@n@` binds `search::score(n)`; EXPLAIN can show `Iterate Index`; score 0 is a real match. | Exact query assets/live representative corpus. |
| R-155 | Lexical snapshot | `CHECKED` design / `NOT IMPLEMENTED` | BM25 order changes with corpus. One bounded top-K statement snapshot; no cross-call lexical cursor. | Context/concurrent-write cases. |
| R-156 | Plain INFO catalog | `CHECKED` exact tests/design / `NOT IMPLEMENTED` | Plain `INFO FOR DB/TABLE` maps hold canonical DEFINE strings. Sort owned keys; compare exact pinned-version strings. `STRUCTURE` is a separate AST-like form and forbidden. | Expected catalog/live readback. |
| R-157 | Bounded streaming restore lease | `CHECKED` source/design / `NOT IMPLEMENTED` | Logical lease plus final/parts directory, fence and manifest handles; finite manifest limits; one verified part handle at a time. | Windows sharing/limit/substitution/crash matrix. |
| R-158 | Base application ID generator | `CHECKED` design / `NOT IMPLEMENTED` | Prefix + canonical 26-char Crockford of 128 OS-random bits; retained before retryable write; collision is integrity failure. | Codec/CSPRNG/regex/collision. |
| R-159 | Derived unique-key encoding | `CHECKED` design / `NOT IMPLEMENTED` | Domain-separated SHA-256 over length-prefixed UTF-8 components. | Golden vectors/mismatch/conflict. |
| R-160 | Field and cross-field invariants | `CHECKED` design / `PARTIAL` exact source / `NOT IMPLEMENTED` | Type coercion precedes ASSERT; row context exposes value/before/after/input/current row. Row-local body XOR/validity/claim/request/slot checks remain operation-rechecked. Broad cross-row invariants are not ASSERT-owned. | Compile exact assets and run positive/negative writes. |
| R-161 | Reader-backed index set | `CHECKED` design / `NOT IMPLEMENTED` | Stream sequence, task/session continuation, memory, forward/reverse link and due-job indexes only. | EXPLAIN/query-plan qualification. |
| R-162 | Explicit work-address projection | `CHECKED` design / `NOT IMPLEMENTED` | Workspace/task/actor/session/call/parent/resource/version explicit; continuation never parses `binding_json`. | Capture projection/query cases. |
| R-163 | Exact DEFINE FIELD grammar | `CHECKED` exact parser/design / `NOT IMPLEMENTED` | Clauses are single-use; DEFAULT and VALUE conflict; FLEXIBLE is legal only immediately after compatible TYPE. Assets use canonical emitted clause order. | Compile all migration assets on exact binary. |
| R-164 | READONLY semantics | `CHECKED` exact tests/design / `NOT IMPLEMENTED` | Initial assignment and same-value replay succeed; changed value fails. READONLY guards update but does not generate/own identity. | Create/same/change matrix for every immutable field class. |
| R-165 | ASSERT boundary | `CHECKED` exact source/tests / `NOT IMPLEMENTED` | String regex uses `$value = /.../`; `TYPE regex` is not string validation. ASSERT is row-local defense; byte digests, replay and set invariants remain application/transaction owned. | Exact row-local assertion corpus. |
| R-166 | DDL transaction coverage | `PARTIAL` | Exact tests prove persisted PARAM rollback and cancelled index overwrite preservation. No evidence yet for the entire selected table/field/analyzer/index wrapper under production transport. | Force failure at each asset boundary and classify catalog. |
| R-167 | Bound metadata values | `OPEN` / `NOT QUALIFIED` | Parser accepts full expressions in DEFINE PARAM, but exact RPC-bound `$bound_*` metadata inside migration wrapper has not been run. | Execute through query-only production client. |
| R-168 | Plan evidence ceiling | `DECIDED` | Correctness never depends on optimizer choice. Slice 0 records query digest/input/EXPLAIN/DTO and may reject unbounded plans for latency, not truth. | Representative cardinality plans. |

## 5. Inference, backup authority и retention

| ID | Объект | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-047 | One-shot ownership | `CHECKED` design / `NOT IMPLEMENTED` | Memory owns semantic job; controller owns authenticated physical call/copies. | P1a. |
| R-053 | Narrow caller | `DECIDED` / `NOT IMPLEMENTED` | Dedicated `memory_inference`; no owner/Agent/automation/plugin fallback. | Registration/denial matrix. |
| R-117 | Stable caller | `CHECKED` design / `GAP` runtime | Stable client ID owns calls across rotation/rollback. | Old-call read/release after rotation. |
| R-125 | Global WriteId | `DECIDED` / `NOT IMPLEMENTED` | ID + client + method + canonical payload; same-ID live replay. | Receipt/call transaction. |
| R-126 | Minimal durable state | `DECIDED` / `NOT IMPLEMENTED` | Reuse receipts; add client/call rows and private call-owned files only. | Schema/runner. |
| R-128/R-129 | Restore inventory/history gap | `DECIDED` / `NOT IMPLEMENTED` | Fixed post-cut interval; below retain cut = history gap. | Stable list/cursor/cleanup. |
| R-132 | Guaranteed retention | `DECIDED` / `NOT IMPLEMENTED` | Monotonic cut constrained by retained backups/unresolved fences. | high-water/list/advance. |
| R-133 | External-ID state | `DECIDED` / `NOT IMPLEMENTED` | Atomic monotonic installation file outside rollback roots; advance before job/send. | Windows state-loss/rollback. |
| R-134 | Auxiliary identity | `DECIDED` / `NOT IMPLEMENTED` | Cancel/release/retention have durable pre-send IDs and cut states. | Readback/recompute. |
| R-135 | Private credential publication | `DECIDED` / `NOT IMPLEMENTED` | Controller owner writes token only to admitted private durable destination. | Install/rotate negatives. |
| R-136 | Admission/auxiliary cut | `CHECKED` design / `NOT IMPLEMENTED` | Drain mutation owner; disposition every external ID before high-water. | Barrier/readback/send denial. |
| R-137 | Cleanup authority | `CHECKED` design / `NOT IMPLEMENTED` | Caller cancel/release; owner-only break-glass; Memory records debt. | Caller/owner cases. |
| R-138 | Membership tombstone | `DECIDED` / `NOT IMPLEMENTED` | Content can erase above cut; bounded membership remains until cut advance. | Inventory/erase. |
| R-139 | In-cut dependency fence | `CHECKED` design / `NOT IMPLEMENTED` | Every admitted call closed/dependent; dependent copies stay unreleased while pinned. | Pre-release recheck/restore. |
| R-141 | Canonical plan digest | `CHECKED` design / `NOT IMPLEMENTED` | Digest excludes itself, publication state and later parts/manifest. | Codec/mismatch. |
| R-144 | Self-contained terminal records | `CHECKED` design / `NOT IMPLEMENTED` | Abort/retire remain terminal after cleanup; malformed/both/mismatch fail closed. | Codecs/prerequisites/restart. |
| R-147 | Concrete process owner/lock order | `CHECKED` design / `NOT IMPLEMENTED` | Daemon owns mutation + backup-set owners; supervisor candidate/cutover. | Owner task/channel/crash. |
| R-148 | Atomic final backup directory | `CHECKED` design / `NOT IMPLEMENTED` | `b_<32hex>`; temp with fence → flush → no-replace rename → parent flush/readback. | Windows directory rename/collision. |
| R-149 | Restore lease/candidate custody | `CHECKED` principle / `SUPERSEDED` unbounded detail | Logical lease/candidate discard retained; all-part handle set replaced by R-157. | Implement R-157. |

## 6. Development-system findings

| ID | Объект | Статус | Решение |
|---|---|---|---|
| R-058–R-067 | Delivery collapse/bureaucracy | `CHECKED` | Connected behavior is denominator; one ledger/integrator; cheap preflight; no object family per noun; replace stale authority. |
| R-049 | Verification order | `DECIDED` | Production code first; fmt + minimum changed-package Clippy after coherent increments; broad suites after connected product. |
| R-059 | Append-only authority | `CHECKED` | Replace stale active text; no errata/report layer. |

## 7. Normative synchronization

| ID | Объект | Статус | Решение |
|---|---|---|---|
| R-024 | Normative synchronization | `CHECKED` design | Architecture 19 / Implementation 42 / Cognition 23 / Contract 0.18 / V3 README agree on product/backup/controller boundaries. Implementation owns exact 3.3.4 schema qualification and proof ceiling. |
| R-076 | Base/Store synchronization | `CHECKED` design / `NOT IMPLEMENTED` | Host/capture/Store/Windows/schema/query/backup baseline synchronized and independent of inference availability. |

## 8. Source coverage added in current passes

| ID | Источник | Статус | Граница вывода |
|---|---|---|---|
| S-056 | Controller `main@613ea6b5`, PR #198, roadmap | `CHECKED` | V2 authority; specification-only; L0/L1 unchecked. |
| S-057/S-073 | Controller issue #200, PR #201, core/API/config/schema validator | `CHECKED` | Allocator/pointer/effect separation; PR fixture-only. |
| S-058 | Controller issue #199 | `CHECKED` | Cross-repository inference owner; blocked. |
| S-059–S-081 | Contracts 0.10–0.18 and synchronized owner sets | `SUPERSEDED` detail or `CHECKED` current boundary | Historical stages established retention, backup owner/lease, FTS/catalog and schema baseline. |
| S-082 | Public DEFINE FIELD 3.3 docs | `CHECKED` public source / `SUPERSEDED` by exact source where available | Initial field design input only. |
| S-083 | Implementation 41 + entrypoints | `SUPERSEDED` qualification detail | Base ID/assertion/index contract before exact-tag audit. |
| S-084 | SurrealDB `v3.3.4` parser/kind/field AST | `CHECKED` exact source | Clause uniqueness/order, FLEXIBLE placement, type grammar and canonical DEFINE rendering. |
| S-085 | SurrealDB `v3.3.4` field runtime + readonly/assert/default/computed language tests | `CHECKED` exact source/tests | READONLY create/same/change behavior; coercion-before-ASSERT; row-local variables; regex expression and computed-field dependencies. |
| S-086 | SurrealDB `v3.3.4` unique-index implementation | `CHECKED` exact source | Tuple containing NONE or NULL bypasses UNIQUE; V3 canonical absence remains an application decision. |
| S-087 | SurrealDB `v3.3.4` PARAM/INFO/FTS/index-cancel tests | `CHECKED` exact tests / `PARTIAL` migration-wide inference | PARAM rollback, index overwrite cancel, plain INFO maps, numbered score, zero-score match and representative `Iterate Index`. Does not prove complete V3 wrapper. |
| S-088 | Implementation 42 + registry | `CHECKED` design | Exact-source facts separated from Slice 0 runtime qualification. |

Existing S-001–S-055 remain historical evidence with their exact recorded scope; no donor is qualified wholesale.

## 9. Current queue

| Priority | Работа | Закрывает |
|---|---|---|
| P0 | Controller #200 implementation and validator acceptance. | R-131 |
| P0 | Keep issue #199 blocked until #200 + V2 L0/L1; never revive V1. | R-048, R-123, R-130 |
| P1 | Write migration 0001 assets, exact wrapper, expected catalog and fixed queries from Implementation 42. | R-006, R-150–R-168 |
| P1 | Slice 0: compile exact grammar; run bound metadata/full DDL rollback/catalog; unique concurrency; query DTO/EXPLAIN; then Windows/process/IPC/Store/files/backup-owner/lease/rollback/rotation/shutdown. | R-002, R-019–R-020, R-083–R-116, R-133, R-141, R-144, R-147–R-168 |
| P1 | Base Slice 1: event→Store/spool→replay→restart→exact open. | R-001–R-013, R-071–R-107, R-158–R-168 |
| P1 | Base Slice 2: Claude relay, continuation, lexical top-K, packet emission, notes/corrections/commitments and maintenance. | R-003–R-045, R-154–R-155, R-162, R-168 |
| P1 | Controller V2 L0/L1. | R-130–R-131 |
| P1 | Inference P1a after foundation. | R-047–R-057, R-117, R-125–R-148, R-157 |
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
| 2026-10-27 / `7a18948d` | Contract 0.16: terminal records, abstract owner/lease and auxiliary cut. |
| 2026-10-27 / `efe86410` | Contract 0.17: daemon backup owner, atomic first visibility, schema/query boundary. |
| 2026-10-27 / Contract 0.18 | Numbered FTS, lexical snapshot, plain INFO, wrapper identity and bounded lease. |
| 2026-10-27 / Implementation 41 | Base IDs, derived keys, assertions, indexes and explicit work-address columns. |
| 2026-10-27 / Implementation 42 | Exact SurrealDB 3.3.4 field/unique/PARAM/INFO/FTS findings; complete wrapper and Windows runtime remain Slice 0. |