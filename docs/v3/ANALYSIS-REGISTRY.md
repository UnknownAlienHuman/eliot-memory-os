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
| R-006 | Six Base tables | `CHECKED` design / `PARTIAL` asset / `NOT IMPLEMENTED` | `stream`, `observation`, `memory`, `memory_history`, `link`, `job`; canonical IDs, immutable fields, reader-backed indexes, fixed DTO queries. Candidate migration/query pack now exists, but exact mutation scripts/cross-field guards/live catalog remain open. | Compile pack; finish mutation assets; live-qualify. |
| R-007 | Current/history | `DECIDED` | Exact version handles; no fall-forward/resurrection. | Publication/restart readback. |
| R-008 | Compound grounds | `PARTIAL` | Required groups, alternatives and advisory support separated. | Reducer/cycle/erase/concurrency. |
| R-009 | Retrieval arms | `CHECKED` design / `PARTIAL` asset / `NOT IMPLEMENTED` | Direct/address/exact/lexical/vector/relation arms independent. Fixed read shapes now concrete; lexical = bounded snapshot, not fake durable cursor. | Compile DTOs, real plans/limits/noise/exceptions. |
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
| R-150 | Schema bundle authority | `CHECKED` design / `PARTIAL` source+asset / `NOT IMPLEMENTED` | Bundle preimage includes format, runner protocol, wrapper, ordered DDL and expected catalog. Candidate transaction body now exists. PARAM rollback and cancelled index overwrite are exact-tag evidence; complete wrapper, bound metadata and all DDL rollback remain unqualified. | Execute exact pack/failure/readback matrix on 3.3.4. |
| R-151 | JSON-safe application/query boundary | `CHECKED` design / `PARTIAL` asset / `NOT IMPLEMENTED` | Canonical string IDs; native record IDs internal; explicit projections/DTOs; no generic codec. Candidate read-query corpus now exists. | Compile DTOs and exact statement digests. |
| R-152 | Base lexical indexes | `CHECKED` source/design / `PARTIAL` asset / `NOT IMPLEMENTED` | Exact analyzer/FULLTEXT syntax and representative index iteration confirmed; candidate analyzer/index/query statements are checked in. | Run exact binary; measure write cost and reader plans. |
| R-153 | Optional unique keys | `CHECKED` exact source/design / `PARTIAL` asset / `NOT IMPLEMENTED` | 3.3.4 UNIQUE skips tuple containing NONE or NULL. V3 writes only NONE for “not applicable”; candidate unique indexes are concrete. | Concurrent insert/conflict through production client. |
| R-154 | Numbered FTS score query | `CHECKED` exact tests/design / `PARTIAL` asset / `NOT IMPLEMENTED` | `@n@` binds `search::score(n)`; score 0 is a real match. Candidate observation/memory top-K queries are concrete. | Exact binary and representative corpus. |
| R-155 | Lexical snapshot | `CHECKED` design / `PARTIAL` asset / `NOT IMPLEMENTED` | BM25 order changes with corpus. One bounded top-K statement snapshot; no cross-call lexical cursor. | Context/concurrent-write cases. |
| R-156 | Plain INFO catalog | `CHECKED` exact tests/design / `PARTIAL` asset / `NOT IMPLEMENTED` | Plain `INFO FOR DB/TABLE` map reads are concrete. Sort owned keys; compare exact pinned strings. `STRUCTURE` forbidden. Expected catalog still requires live canonical output. | Generate/verify expected catalog from exact run. |
| R-157 | Bounded streaming restore lease | `CHECKED` source/design / `NOT IMPLEMENTED` | Logical lease plus final/parts directory, fence and manifest handles; finite manifest limits; one verified part handle at a time. | Windows sharing/limit/substitution/crash matrix. |
| R-158 | Base application ID generator | `CHECKED` design / `PARTIAL` asset / `NOT IMPLEMENTED` | Prefix + canonical 26-char Crockford of 128 OS-random bits; candidate field assertions encode exact ID shape. | Codec/CSPRNG/regex/collision. |
| R-159 | Derived unique-key encoding | `CHECKED` design / `PARTIAL` asset / `NOT IMPLEMENTED` | Domain-separated SHA-256 over length-prefixed UTF-8 components; candidate fields/indexes now concrete. | Golden vectors/mismatch/conflict. |
| R-160 | Field and cross-field invariants | `CHECKED` design / `PARTIAL` exact source+asset / `NOT IMPLEMENTED` | Candidate pack includes safe per-field guards only. Body XOR, validity, address digest, claim/request/slot tuples remain fixed-writer and exact negative-test obligations; guessed cross-field ASSERT was intentionally not added. | Finish exact writer scripts; qualify row-local expressions before promotion. |
| R-161 | Reader-backed index set | `CHECKED` design / `PARTIAL` asset / `NOT IMPLEMENTED` | Stream sequence, task/session continuation, memory, forward/reverse link and due-job indexes are concrete. | EXPLAIN/query-plan qualification. |
| R-162 | Explicit work-address projection | `CHECKED` design / `PARTIAL` asset / `NOT IMPLEMENTED` | Workspace/task/actor/session/call/parent/resource/version fields and task/session queries are concrete; continuation never parses `binding_json`. | Capture projection/DTO cases. |
| R-163 | Exact DEFINE FIELD grammar | `CHECKED` exact parser/design / `PARTIAL` asset / `NOT IMPLEMENTED` | Clauses are single-use; DEFAULT and VALUE conflict; FLEXIBLE placement exact. Candidate assets use selected canonical order. | Compile every migration statement on exact binary. |
| R-164 | READONLY semantics | `CHECKED` exact tests/design / `PARTIAL` asset / `NOT IMPLEMENTED` | Initial assignment and same-value replay succeed; changed value fails. Candidate immutable field classes now explicit. | Create/same/change matrix. |
| R-165 | ASSERT boundary | `CHECKED` exact source/tests / `PARTIAL` asset / `NOT IMPLEMENTED` | Candidate uses only simple per-value regex/range/closed-state assertions. Cross-field/set invariants remain application-owned until live qualification. | Exact positive/negative corpus. |
| R-166 | DDL transaction coverage | `PARTIAL` | Exact tests prove persisted PARAM rollback and cancelled index overwrite preservation. Candidate complete transaction exists but has not run. | Force failure after each table/field/analyzer/index boundary. |
| R-167 | Bound metadata values | `OPEN` / `NOT QUALIFIED` | Candidate wrapper binds `$bound_*` in three DEFINE PARAM statements; production RPC execution remains unrun. | Execute through query-only client. |
| R-168 | Plan evidence ceiling | `DECIDED` | Correctness never depends on optimizer choice. Slice 0 records query digest/input/EXPLAIN/DTO and may reject unbounded plans for latency, not truth. | Representative cardinality plans. |
| R-169 | Design-only migration asset pack | `DECIDED` / `NOT QUALIFIED` | `store/0001-base.surql` makes six tables, selected fields, indexes, analyzer and metadata wrapper concrete without claiming runtime admission. | Parse/execute exact bytes; produce live catalog. |
| R-170 | Fixed read-query asset pack | `DECIDED` / `NOT QUALIFIED` | `store/queries-base.surql` contains explicit source/current/history/relation/continuation/FTS/job/backup/catalog read shapes; runtime embeds named blocks only. | Split/embed, digest, decode and EXPLAIN each selected block. |
| R-171 | Mutation-script and cross-field gap | `OPEN` / `NOT QUALIFIED` | Pack intentionally omits guessed IF/THROW branching for capture/revision/job mutation and unrun row-cross-field ASSERTs. These remain the next asset work, not hidden prose completion. | Write exact mutation scripts from production operation semantics and run failure matrix. |

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
| R-024 | Normative synchronization | `CHECKED` design | Architecture 19 / Implementation 42 / Cognition 23 / Contract 0.18 / V3 README agree on product/backup/controller boundaries. Store candidate pack is explicitly subordinate and design-only. |
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
| S-089 | `docs/v3/store/` candidate pack | `CHECKED` design artifact / `NOT QUALIFIED` runtime | Concrete migration/read-query inputs subordinate to Implementation; mutation branching, cross-field guards, expected catalog and live execution remain open. |

Existing S-001–S-055 remain historical evidence with their exact recorded scope; no donor is qualified wholesale.

## 9. Current queue

| Priority | Работа | Закрывает |
|---|---|---|
| P0 | Controller #200 implementation and validator acceptance. | R-131 |
| P0 | Keep issue #199 blocked until #200 + V2 L0/L1; never revive V1. | R-048, R-123, R-130 |
| P1 | Compile/execute candidate migration and read-query pack; add exact capture/revision/job mutation scripts, row-cross-field guards and expected catalog from the pinned run. | R-006, R-150–R-171 |
| P1 | Slice 0: bound metadata/full DDL rollback/catalog; unique concurrency; query DTO/EXPLAIN; then Windows/process/IPC/Store/files/backup-owner/lease/rollback/rotation/shutdown. | R-002, R-019–R-020, R-083–R-116, R-133, R-141, R-144, R-147–R-171 |
| P1 | Base Slice 1: event→Store/spool→replay→restart→exact open. | R-001–R-013, R-071–R-107, R-158–R-171 |
| P1 | Base Slice 2: Claude relay, continuation, lexical top-K, packet emission, notes/corrections/commitments and maintenance. | R-003–R-045, R-154–R-155, R-162, R-168–R-171 |
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
| 2026-10-27 / Store candidate pack | Added design-only `0001-base.surql` and fixed read-query corpus; exact mutation/control-flow scripts, expected catalog and live qualification remain open. |