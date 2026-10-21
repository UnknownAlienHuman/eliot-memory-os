# Eliot Memory OS V3 — Implementation

**Revision 0.23 · 2026-10-21 · design for the greenfield implementation.**

[Architecture](ARCHITECTURE.md) defines the product; [Cognition](COGNITION.md) defines its cognitive algorithms. [Audit §36](AUDIT.md#36-disagreement-research-and-self-revision-023) grounds the self-diagnosis, disagreement and research paths added in §§7.5,8.6–8.7. [§35](AUDIT.md#35-autonomous-understanding-without-a-compulsory-pyramid-022) covers project understanding; [§34](AUDIT.md#34-native-store-operations-without-mirrored-state-021) native persistence; [§33](AUDIT.md#33-controller-execution-and-embedding-boundary-020) external execution. [Audit map](AUDIT-MAP.md) records actual reading and remaining work. These are design choices, not an installed schema or implemented V3.

## 1. Initial delivery

### 1.1 Runtime and module shape

Begin with one Rust package, an executable with service/CLI/relay modes, and ordinary modules. Split a crate only for an actual dependency, deployment or change boundary.

| Module | Work |
|---|---|
| `store` | Schema, parameterized queries, transactions and mutation readback |
| `memory` | Capture, semantic revisions, sources and correction |
| `context` | Retrieval, applicability and packet assembly |
| `learning` | Procedures, improvement lessons and outcome reduction |
| `jobs` | Finite background memory work and result application |
| `adapters` | Actual host, source and controller interfaces |
| `control` | Configuration, maintenance, status and recovery |

SurrealDB is the server child of `eliotd`. One private Store owns application writes and uses native indexes, relations and transactions. Do not reproduce Kernel, storage bridge, named-operation catalogue, generic query language or a second semantic database. These module names organize code; they are not seven servers or seven mandatory service interfaces. Start with concrete functions and add an adapter only at an actual external boundary.

The first target is local Windows. Reuse a host/controller supervisor when it actually observes Eliot's process and failures. Otherwise a small supervisor mode of the same binary owns daemon and database. The standalone profile has three owned processes; the relay is transient. Do not build two supervisors for the same tree.

### 1.2 Demand-start and immediately useful memory

One OS single-instance boundary per data directory serializes startup. Once primary storage is available, capture, direct reads and lexical context work. They do not wait for a project-wide rebuild, a graph-size threshold, a readiness certificate, embeddings, Dreamer or diagnostic persistence. Optional capabilities improve this path rather than authorize it.

Use database indexes over primary searchable records as the first implementation. A second application-owned cue snapshot and publication coordinator are not prerequisites. If a measured optimization later adds a cache, its absence or staleness falls back to primary queries instead of switching memory off. An unrelated project revision does not invalidate every remembered fact.

Idle shutdown stops new external dispatch, settles short mutations, retains pending work and stops owned processes. Planned shutdown stays stopped. No SCM installation or scheduled OS wake is required by default; due work runs while active or on the next demand start. Vectors remain part of the full product, but their outage does not turn existing memory into an empty bank.

### 1.3 One database client

Use the official network-capable Rust SDK, private to Store, with one compatible SDK/server pair and the necessary network/TLS features. The documentation reference profile is server **3.3.4** and Rust SDK **3.3.4**, checked on 2026-10-21: [server release](https://github.com/surrealdb/surrealdb/releases/tag/v3.3.4), [SDK reference](https://surrealdb.com/docs/reference/rust). The latter specifies Rust 1.95 or newer. This selects the API/syntax being designed against; no dependency lock, Windows build or installation is claimed.

Start with one reusable remote WebSocket connection and the documented `protocol-ws` feature; do not enable embedded `kv-*` engines for this server-child profile. [Transport reference](https://surrealdb.com/docs/reference/rust/methods/connect). Select the actual TLS features with the implementation rather than imply a measured dependency-size reduction from this document. A second HTTP/gRPC abstraction is unnecessary for the initial paged operations.

The old [Phase A ADR](../ADR/0001-phase-a-dependency-boundaries.md) is donor history, not a V3 veto. A concrete unresolved dependency or platform problem may justify an ordinary JSON-RPC client instead; choose one client, not a compatibility framework around both.

Check the actual statement errors and expected changed rows. A successful transport or zero-row conditional update is not a committed mutation. Keep these checks beside the query. [SDK query reference](https://surrealdb.com/docs/reference/rust/methods/query).

## 2. Minimal data and ownership

### 2.1 Record families

| Family | Necessary information |
|---|---|
| Observation | Source event/revision, preserved content or blob, scope and available time |
| Memory revision | Content, kind, sources, material conditions and current exposure |
| Link | Evidence, live dependency, contradiction, replacement or navigation |
| Attempt/outcome | Method revision, actual action, criterion and observed result/coverage |
| Job | Purpose, input/method, progress, current worker and optional external request |

These are logical families, not an instruction to make exactly five tables. Store mutation readback with the owning record/job where possible; add a separate operation row only when necessary. Pure helpers and reads do not require a generic Operation lifecycle.

Keep semantic history as application revisions, not an assumed database undo log. Save referenced large blob bytes before publishing their reference and remove unreferenced leftovers later. Preserve originals independently of model prompt length. When capture kept only a prefix, tail or external handle, say so. Include controlled blobs in backup/deletion.

### 2.2 Identity and time

Bind sessions to their configured workspace. Preserve source event identity across retries; the same ID with different content is a conflict, while independent identical events stay separate. Retain original spelling and derive lookup forms separately. Uncommitted worktree state is not committed HEAD.

Occurrence, receipt and validity time are different. Unknown time remains unknown. Intended behavior, observed behavior and explanation are different perspectives. A hypothesis can be useful without becoming a verified fact.

### 2.3 Read remembered knowledge without re-proving the world

Ordinary reads return stored observations and applicable remembered material with known qualifications. They do not synchronously re-read every source, prove the whole lineage or rebuild the project before answering. Check the addressed records' actual visibility and known withdrawal state; use recorded conditions and cheaply available source information. Missing fresh verification means an explicitly historical or conditional answer where useful, not denial of all memory.

Refresh an affected claim/view separately when current facts matter. Distinguish historical evidence from live requirements: changing an unrelated file does not erase a lesson. A known false premise needs correction or a new derivation, not removal of its citation from unchanged prose. Cognition specifies conflicts and qualified current-state resolution.

The local profile needs configured projects, capture exclusions, retention and allowed model routes, not an organization/principal/grant hierarchy. A local-only source is not sent to a remote model. Group compatible model inputs and retain their sources for correction/deletion; a model's omission of a citation does not declassify its input. Already disclosed provider or host copies are outside a local erase operation.

### 2.4 Checks with an actual purpose

Use stable IDs, database transactions and relevant expected revisions for updates. Hashes may identify actual immutable payloads, cache inputs and backup components. They do not prove understanding or confer authority. No normalization envelopes, signed read receipts, per-helper policy digests, authority epochs or proof matrices are required.

Keep normal OS/file permissions, database credentials and the host's configured tool permissions. The local application is not a sandbox against an unrestricted process under the same OS account; do not invent an ineffective security subsystem around that limitation.

### 2.5 Exact cues and advisory aliases

Interpret a path using the adapter's actual source syntax and base. Retain unresolved distinctions between relative, rooted, drive-relative, drive-absolute and UNC forms. Missing path context does not reject raw capture. Use native/library path handling, not a new cross-platform path language.

Symbols follow their source language. Case-insensitive and punctuation aliases can find candidates but are not exact entity equality. Preserve original forms and use the same comparison behavior on capture and query. A command-family cue retrieves a lesson; it is not enough to prohibit an action. A normalization change rebuilds derived lookup data, not the original observation.

### 2.6 Initial physical layout

The following is the selected starting layout for the capture-to-lesson path, not an arbitrary table-count ceiling for the entire OS. Each row has one meaning and one Store writer. Declare types for fields used in identity, filtering and ordering; retain source-specific input in an ordinary payload instead of inventing a schema family for every tool.

| Table | Actual data | Required lookup |
|---|---|---|
| `stream` | Configured source/session identity, project scope and last local ingestion sequence | Stable stream ID; no project-wide truth revision |
| `observation` | Original event key, stream, ingestion sequence, available occurrence time, body/blob and actual call/parent/task references | Unique `(project, stream, event_key)`; ordered `(project, stream, ingest_seq)`; native text index over captured searchable text |
| `memory` | Stable item ID, current editorial revision, kind, content/search text/cues, subject/aspect/perspective, applicability/time and exposure | Direct ID; scoped comparison group; native full-text index; compatible optional vector |
| `memory_history` | A previous semantic revision of that item, archived once when replaced | Unique `(item, revision)`; paged item history |
| `link` | Native relation endpoints, purpose and the addressed memory revision at each versioned endpoint | Endpoint/kind/revision lookup in either useful direction |
| `job` | Transformation purpose/target, method, finite input, state, current claim, external references and applied result references | Due work; pending/running work for the same purpose/target; direct job readback |

`memory` is the primary working record, not a cache requiring a second publisher. `memory_history` stores previous revisions; it is not another mutable current copy. Archive the replaced semantic fields, not a second set of derived vectors. A version handle is `(item_id, revision)`: `open` reads the current row if that revision matches, otherwise the exact historical row. A missing or withdrawn current row does not authorize selecting the newest historical row as current.

Editorial revision is not world-state authority. Several incompatible claims can remain separate items in the same comparison group. Revising one procedure does not supersede all claims about its resource. Observed validity, receipt time and the reasons for replacement retain their existing meanings from Cognition §3.

Links to a memory item carry the material source revision when their meaning depends on it. Reading an old lesson must not silently cite the new text of its edited premise. Keep historical links associated with their originating revision; publish the links for a new revision with that revision. A relation supplies navigation, evidence or a live requirement according to its kind, not all three automatically. Do not maintain a separate source-ID array and independently mutable edge registry as competing authorities.

An actual execution result remains an `observation`. An interpreted method/attempt/criterion assessment can be an ordinary versioned `memory` item with that tuple as its lookup key and links to the result. Repeated delivery updates neither the independent case count nor a second execution ledger. Aggregate effectiveness and status remain queries/views. No `SkillRegistry`, `TruthStore` or separate outcome database is needed.

For a large external payload, preserve its blob and exact source handle. A bounded searchable excerpt is not a claim that all bytes were indexed. Add source-linked derived chunks only when that ingestion path needs them; do not copy the complete body into every lesson or confuse a chunk with a new observed event. Physical erasure includes the relevant current/history rows, links and controlled blobs under §10.

### 2.7 Five concrete Store operations

These are ordinary methods and parameterized query files inside `store`, not a public named-operation registry, generic query builder or another process. The single application mutation owner serializes short write transactions. Source reading, model execution, embeddings and large file preparation happen outside those transactions; reads need not wait for a model.

| Operation | Work committed together | What is not required |
|---|---|---|
| `capture(event)` | Preserve the new source event, assign its local stream position and insert/extend necessary pending work | Semantic classification, vector generation, a project map or a write-plan certificate |
| `claim_due()` | Freeze the chosen finite input and assign this job to the current worker; retain any unclaimed remainder | A project-wide queue barrier or a new task-graph engine |
| `apply(job, proposal)` | Publish addressed memory/history/links and the actual result/processed input of that job | Re-running inference just because the DB acknowledgement was lost |
| `find(request)` | Read independent candidates, relevant alternatives and selected relations | A write receipt, full history replay or global search-publication state |
| `open(handle)` | Read the addressed current/historical item or source segment under its actual scope | Regenerating a plausible substitute for missing content |

**Capture and replay.** The adapter supplies the upstream event identity, or allocates one before its first delivery/spool write. A stream distinguishes actual source/session/agent streams; an event key includes a source revision when that source's IDs are mutable. Within the capture transaction, an existing key with the same source input returns the existing observation and does not enqueue the work again. Different input under that key is a concrete conflict or explicit correction, not an overwrite. Content equality alone does not merge independent occurrences.

For a new event, advance the stream's local ingestion sequence, save the observation, and create or extend appropriate pending work before commit. This position is for delivery/progress only: a late imported old event receives a new ingestion position while retaining its old occurrence time. Do not use `occurred_at` as the processed watermark. A sparse sequence is acceptable; there is no need to prove that every integer exists. Return the actual primary/staged/unknown result; a wakeup only accelerates the worker.

**Finite work under continuing input.** Keep one running job and at most one coalesced pending successor for the same purpose/target. Capture can extend the pending successor, never the input of the running job. Claim a bounded prefix using saved event identity/order and useful call/result boundaries; leave any remainder pending. The existing single mutation owner makes this a short read/update, not a distributed admission protocol. Independent targets can run concurrently.

A job retains the actual source IDs or bounded stream ranges and the named existing item revisions supplied for interpretation. If only positions 1–12 were supplied, it cannot mark 1–20 interpreted. If events 21–24 arrive while work on 1–20 runs, completing that job leaves 21–24 pending. This example describes the design, not an executed test. The same originals remain available for a later distinct purpose or deliberate reinterpretation; there is no universal `processed=true` on an observation.

**Amendment and completion.** Prepare the model result before opening the transaction. On application, check the addressed current item revision and the current job claim; archive the predecessor, update the existing item, add the new source/replacement links and finish the job for exactly its supplied input together. A direct user correction uses the same memory-write functions with its captured event as the repeat identity; it does not need a fabricated model job. Genuinely independent proposal subsets may be applied explicitly as partial under §6.3.

Use an explicit `BEGIN TRANSACTION` / `COMMIT TRANSACTION` around dependent statements. [SurrealDB transactions](https://surrealdb.com/docs/learn/querying/concepts-and-guides/transactions) are not implied by putting several top-level statements in one SDK request. An in-transaction `UPDATE ... WHERE revision = $expected RETURN AFTER` must change the intended row; otherwise throw inside that transaction so preceding dependent writes do not remain. `UPDATE` can succeed with zero rows. Do not replace this with `UPSERT`, which may create an absent record. [UPDATE](https://surrealdb.com/docs/reference/query-language/statements/update) · [UPSERT](https://surrealdb.com/docs/reference/query-language/statements/upsert).

Snapshot isolation is not a promise that every previously read predicate is protected from another writer. Keep the chosen single mutation owner and relevant row checks; do not infer global serializability from the word transaction. Native write/unique-index conflicts are handled at this short operation. A conflict means reread the affected input/target and decide whether the prepared proposal still applies, not blindly replay a paid external call or force stale text into the new revision.

After a lost commit acknowledgement, read the same event key or job/result reference. If application committed, return those saved references rather than create a second lesson. A successful explicit keep completes that job without inventing a memory revision. Missing pages, invalid output and provider failure do not advance its interpreted range. Persist the useful external result before releasing an executor whose body is otherwise temporary; §6 defines that external boundary.

### 2.8 Direct reads and native indexes

The query shapes below are design sketches for the stated 3.3.4 profile, not executed migrations or a verified query plan. Bind IDs as typed record values and text as parameters. Page by the actual ordering key with a fixed upper bound for that read, not a fixed oldest prefix or a growing offset into unrelated records.

```surql
-- An exact address does not depend on the search index's state.
SELECT * FROM $item WHERE project = $project;

-- One finite original-input range; later arrivals remain for a later range.
SELECT id, event_key, ingest_seq, occurred_at, body, blob_ref
FROM observation
WHERE project = $project AND stream = $stream
  AND ingest_seq > $after AND ingest_seq <= $through
ORDER BY ingest_seq ASC
LIMIT $page_size;

-- Current editorial records, not a replay of every past snapshot.
SELECT id, revision, text, search::score(0) AS score
FROM memory
WHERE project = $project AND exposure = 'normal'
  AND search_text @0@ $query
ORDER BY score DESC, id ASC
LIMIT $candidate_limit;
```

The last query illustrates one configured lexical policy, not a universal rule that every word must match. Exact cues, lexical candidates and compatible vectors are independent inputs to the existing context compiler. A valid full-text match may have a BM25 score of zero, especially in a small or repetitive corpus; do not turn `score > 0` into a requirement for being remembered. Use a deterministic tie order. This is a native-search consideration, not a newly demonstrated zero-score defect in the old Eliot query.

Define separate indexes for source-key uniqueness, ordered stream reads, scoped claim-group lookup, full-text fields and actual relation lookups. In SurrealDB 3.x the documented full-text clause is `FULLTEXT ANALYZER`, not the old `SEARCH ANALYZER`. Array cue lookup must use the actual supported element-index shape, not assume an arbitrary index on an array serves every predicate. [Native index reference](https://surrealdb.com/docs/reference/query-language/statements/define/indexes).

Use native maintained indexes on the actual primary fields. Initial concurrent index construction and normal transactional index maintenance are different: a building index may be unavailable, but it is not a reason to deny direct ID/source reads. Do not re-create `memory_search_projection`, project-wide matching revision rows and a publication queue merely to expose text that is already committed. Inspect `EXPLAIN` for the selected queries during implementation; native syntax alone is not measured performance.

Retrieve the relevant claim group's alternatives and the required source/relationship neighbors before final packing. Fetch payloads only for those records. An exact historical handle opens its exact version; normal recall prefers the working records and intentionally selected history, not whichever first 512 physical rows happen to load. Whole-history enumeration has continuation. The scoped current-state resolver in Cognition, not a newest-timestamp shortcut, decides applicability.

### 2.9 Derived vectors do not become a second publication authority

Start with one configured active encoder profile for a given vector field/index. The current vector carries the content revision and encoder/preprocessing profile from which it was produced. The corresponding query vector uses that same profile. The native index dimension is chosen from the actual encoder, not inferred from the Dreamer model name.

When searchable content changes, commit the new text and clear the obsolete vector reference in the same memory mutation; schedule the existing embedding work. The new lesson is already available through direct and lexical reads. Apply returned vectors only to their still-current content revision/profile. A late vector for an old revision is not silently attached to the new text. Storing a vector is a derived-data update, not a new semantic lesson, independent confirmation or trigger for another reflection.

For the initial implementation, changing encoder can temporarily disable that vector arm while rebuilding the derived values/index for the new profile. Exact/lexical access continues. This is a deliberate simpler choice, not a promise of uninterrupted ANN service or a requirement for permanent dual encoders. Do not mix incompatible vectors to make the route appear ready, and do not wait for a whole-corpus embedding certificate before returning independent useful results.

## 3. Host interface and experience intake

### 3.1 Small application surface

| Operation | Purpose |
|---|---|
| `attach` | Bind a workspace and report actual host capabilities |
| `capture` | Preserve an event; return committed, staged, unknown or rejected |
| `context` | Assemble useful context for a goal/decision and budget |
| `open` | Expand a stored handle or report the specific missing material |
| `record_outcome` | Submit an observed result or explicit report through the capture path |
| `dream` | Request interpretation, consolidation or improvement |
| `control` | Inspect, pause/cancel, configure, correct, restore or erase defined memory |

CLI, MCP and hooks reuse these functions. Metadata comes from adapters where available; agents do not administer claims, manufacture proof objects or complete a questionnaire before ordinary capture. An ambiguous project can use a narrow session scope. Non-Git sources use available anchors.

`record_outcome` is a convenience input to capture, not a second execution ledger or a proof-producing service. A host result is retained once and referenced by learning, history and status views. Explicit human/agent reports retain their source as reports; they do not become independently observed execution. Do not generate successful steps, verifier names or new project IDs to fill a result form. Missing execution is not a successful execution record.

### 3.2 Capture and deferred input

Capture permitted raw events before classification. Save stable identity, content and necessary follow-up intent in one transaction. Semantic ambiguity, missing embeddings and model failure do not prevent preservation. A correction retains its connection to the original rather than becoming another independent event.

When primary storage is unavailable or paused, a small file spool retains delivery input. Publish one complete event file under its stable ID using ordinary atomic file publication and the platform's actual durability primitives. Temporary preparation happens outside a short ingress lock; publication uses the current active directory. A staged acknowledgement means the input was saved, not that semantic processing finished.

Replay uses normal capture and the same IDs. Remove staged input after primary commit or a relevant recorded deletion. Lost answers use readback, not new identities. Enforce actual storage capacity and return a truthful failure on disk-full. A page-size choice is not a total project-memory limit.

### 3.3 First host and actual timing

Use native Claude Code hooks for events and context delivery, with MCP for requested lookup/expansion. The [official hook reference](https://code.claude.com/docs/en/hooks), consulted 2026-10-20, documents `PostToolUse`/`PostToolUseFailure` inputs including call identity and result/error. Preserve those actual inputs with their bound session/workspace; read an additional transcript segment only when needed for the episode. Do not ask a model to manufacture an execution proof for an event the host already emitted. Tool completion is not whole-task success.

Serve orientation on `SessionStart`/`UserPromptSubmit`. When the installed host supports `PostToolBatch`, use its native after-batch/before-next-model boundary for context informed by several tool results, rather than inserting repeated per-tool coordination. On hosts without that event, retain the existing supported boundaries; do not build a compatibility scheduler merely to imitate it. This is a documented integration choice, not a claim that the owner's installed host was exercised.

The hook path captures and retrieves; it does not wait for Dreamer. New saved episode material makes existing background work due. A turn-end signal may wake that work, but does not force another agent turn or a compulsory reflection. Model processing happens off the foreground path.

Advice in `PreToolUse` cannot be assumed to change an already chosen call. **Negative memory is advisory by default.** Eliot does not insert an automatic approval or denial gate before every tool. A specific host-enforced rule is opt-in and separate from memory retrieval. Use available call/event IDs instead of pairing interleaved results by latest timestamp; unknown correlation stays unknown.

### 3.4 Independent capabilities

Capture, advisory delivery, optional host enforcement, result observation and cancellation are separate capabilities. One unavailable extension does not disable the working ones. A search-only host is useful without pretending to demonstrate the entire learning loop. Maintenance completes memory work, not a fictitious coding task.

### 3.5 Optional enrichment cannot rewrite a completed operation

After a primary handler has produced a known result, optional advice, measurements, logging or response decoration cannot replace it with a generic failure suggesting nothing ran. Return the primary result; report a useful enrichment gap separately. Never retry the original effect to repair telemetry.

Failed primary persistence still is a failure. If an external effect happened but its required local recording failed, distinguish the known effect from the recording gap or genuinely unknown outcome. No extra status service is needed.

### 3.6 Delivery and repeat suppression

Build the packet before optional accounting. Prepared, locally handed off and actually observed by a host are different events. Record only what was observed; do not mark delivered before sending and restore that mark later as proof of receipt. Logging failure need not suppress useful advice.

Keep repeat suppression as a small presentation cache keyed by context incarnation and material revision. Resume, a lost cache, a changed relevant item or a previously unready orientation permits a current re-offer. A permanent `boot_sent` flag must not hide newly available understanding for the rest of the session. Re-offering is not new learning evidence and does not justify sending everything on every call.

## 4. Retrieval and context

### 4.1 Independent candidates and truthful resolution

Query exact identifiers and lexical fields on primary records independently of vector candidates. Merge their IDs with compatible vector results; a lexical hit does not need a dense score. Resolve relevant current alternatives by the indexed claim group, not only semantic top-k. Cognition owns that resolver.

Hydrate selected IDs and genuinely needed alternatives/neighbors. Do not load every project payload to fill a small response. Keep native searchable fields with the record wherever practical; do not first create a mirrored search store and then a recovery framework to keep it current.

Scope queries before disclosure. Use the actual database's filtered vector facilities; check its query plan before inventing a fallback engine. Small exact vector search is a legitimate option. [Similarity-search reference](https://surrealdb.com/docs/learn/data-models/vector-search/similarity-search).

For broad listing/onboarding, return useful pages with continuation rather than failing after a corpus-wide 10,000-row cap. A full scan becoming partial must not invalidate independently retrieved records. A malformed or unavailable selected item is reported for that item where the rest of the response remains meaningful.

### 4.2 Embeddings

Bind vectors to their encoder, dimension, preprocessing and content revision. Equal dimension is not compatibility. A Dreamer model change does not imply changing the embedding model or reindexing everything.

Match batch outputs to requested items and reject misassigned, missing or invalid vectors without discarding preserved content. Apply an independent valid subset as partial. Build a new encoder's derived index coherently; exact/lexical reads continue meanwhile. Remote query embedding is a network/model call and need not block a synchronous advice hook.

### 4.3 Pack a decision, not unrelated snippets

Include useful goal/criteria, current state, experience, material exceptions, uncertainty and next checks. Empty sections add nothing. Keep qualifications with claims; reveal detail through handles. A long source does not require either dumping everything or refusing the whole answer.

Graph traversal is optional expansion from relevant seeds, not a prerequisite for exact hits. Do not load the whole graph, require a minimum total edge count or persist an ActivationTrace before returning direct context. A single relevant relation can already be useful. If expansion is unavailable or adds nothing, return the direct result. Explanation/debug data can describe the traversal without an obligatory write on every read.

Account for total injected/repeated context and reconstruction work when evaluating cost. Reading or retrieving a record does not strengthen its factual support.

## 5. Finite background work

### 5.1 One existing job mechanism

Jobs retain purpose, actual inputs/method, progress, current worker and any external execution reference. A local claim, provider execution and memory mutation are distinct facts, not three standalone managers. Use a small set of ordinary work states and reasons.

### 5.2 Independent work stays independent

Claim a due job, compute outside the transaction, then conditionally publish its result and finish it. Check the actual current claim and affected input/target revisions when changing existing state. An expired worker cannot overwrite newer work; cancellation and completion meet on that job. These are local concurrency checks, not global authority epochs.

Do not place all project work behind its oldest unapplied row. A failed map refresh must not block an unrelated procedure, capture or search. Preserve ordering only for transformations that actually depend on earlier outputs. Independent targets can run concurrently. No new task-graph engine is needed.

Coalesce wakeups, not observations. Capture each event, then process the relevant unprocessed episode range; replacing a pending trigger with the latest message must not discard earlier unprocessed turns. Advance progress for inputs actually processed and committed. A running finite batch can finish; new input goes into its successor. Debouncing must not postpone every useful consolidation indefinitely during continuous activity.

A successful no-change result finishes work for those inputs/method. Reuse it until something relevant changes. Invalid output, missing input and an unavailable provider are not no-change.

### 5.3 External execution and retries

Retain an external request reference before dispatch where the controller supports it. A new worker first reads the existing execution rather than buying another call. Controller owns provider attempts; memory owns applying the returned content.

When durable readback/idempotency is unavailable, report that route's limitation rather than inventing a guarantee or disabling every model. A permitted repeated pure inference is another charged execution; unknown external effects are not blindly replayed. Account for late/unknown usage even if the result is no longer applicable.

### 5.4 Enqueue and wake

Insert necessary follow-up work with its primary change. Poll due work with ordinary bounded concurrency; notifications merely accelerate wakeup. Do not require a second scheduler, readiness registry or capacity ledger. A table event is an alternative enqueue implementation, not a guarantee of retries and execution.

Reserve useful service for capture/control/outcomes during bulk work. Import/rebuild reconciles the derived tasks it needs. Model or graph maintenance failure cannot undo primary capture or independently working retrieval.

## 6. Dreamer through controller

### 6.1 Actual integration boundary

The controller was read at `912df90f86320ff556c1dba23badc2c69e518e34` on 2026-10-21. Its [Memory OS integration document](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/912df90f86320ff556c1dba23badc2c69e518e34/docs/eliot-memory-os-integration.md) still describes a future controller-to-memory context request, not the reverse inference connection. The positive [method registry](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/912df90f86320ff556c1dba23badc2c69e518e34/crates/swarm-contracts/src/method_policy.rs) exposes agent execution and result reads; no dedicated vector-embedding method was found there. Do not label both capabilities implemented merely because a controller connection exists.

Use the controller's existing authenticated client/IPC and selected execution route. Memory OS does not copy its Store, native adapters, provider loop or admission envelopes. The concrete initial text mapping below uses a genuine finite synthesis Task. This is a design choice over inspected source capabilities, not a completed integration or a requirement that every future executor expose Task objects.

### 6.2 Request and result

The memory-side request contains a stable request key, configured route, finite saved input, method/output expectation and relevant cost/disclosure settings. The job retains the returned external references and later reads that same execution. It does not maintain a parallel copy of every controller state. Input contains real event text or handles the executor can actually open, not source IDs presented as contents.

| Step | Existing controller operation | Memory-side meaning |
|---|---|---|
| Prepare execution | `agent.open` with lane and route | Obtain the binding; this prepares an executor, not a model answer |
| Describe the work | `task.create` and `task.claim` for the selected binding | One real episode-interpretation task with a useful objective/output; group related input, not one task per captured event |
| Start that work | `task.dispatch` with the actual Attempt and text | Save its Operation reference; queued or native input admitted is not completed inference |
| Observe the outcome | Existing state/event reads and the route's result selector | Distinguish completed, failed, still running and unknown; do not ask the model to repeat its answer |
| Read the output | `agent.result`, then retained `artifact.read`/pages; assemble when needed | Obtain the actual response bytes for this input, not a status description or the latest unrelated reply |
| Apply useful content | Existing memory revision/job transaction | Save create/amend/keep and the processed source range; controller Task acceptance is not proof of semantic truth |

A synthesis Task's objective is interpretation of the supplied episode, not fictitious code modification. The inspected [TaskSpec and admission](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/912df90f86320ff556c1dba23badc2c69e518e34/crates/swarm-kernel-host/src/model.rs#L420-L545) permit absence of an acceptance policy; do not add fake verifier, Git commit or test-result fields to get an advisory back. Actual controller authorization and route setup still apply. Direct `agent.open` is not the workspace-leasing `swarm.launch` path; an executor's configured working directory does not require a new worktree for every memory job.

The controller [TaskPrompt builder](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/912df90f86320ff556c1dba23badc2c69e518e34/crates/swarm-kernel-host/src/store/task_prompt.rs#L175-L270) appends the real Task identity and brief. This route is not an unwrapped text-completion API. Describe the interpretation once, keep the supplied sources distinguishable from its instruction, and do not require the model to manufacture controller metadata.

**Concrete route limit.** In the inspected [Claude bridge](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/912df90f86320ff556c1dba23badc2c69e518e34/modules/claude/bridge-v6.mjs#L400-L580), the first model query requires `task.dispatch`; later `agent.send` is a real next turn. However, its [result-page reader](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/912df90f86320ff556c1dba23badc2c69e518e34/modules/claude/result-pages.mjs) accepts a `claude_assistant_result` origin whose target method is `task.dispatch`. Do not implement recurring Dreamer work as arbitrary sends on this route while assuming the same result reader covers them. Reuse a route only for a request/result pairing it actually supports; extend the existing controller adapter when a needed pairing is missing, rather than ask the agent to restate an answer or build a second transcript scraper in Memory OS.

A result page is not the complete response. Follow its continuation for the same input and preserve result identity across pages. The selected Claude reader caps pages at 65,536 bytes and the source body at 512,000 bytes; these are inspected adapter limits, not universal Eliot limits. Its not-yet-copied body is boot-local and resume/recover is unavailable. Read and retain useful output before releasing that executor; a worker loss cannot be repaired by calling a nonexistent durable result API. Other routes have their own behavior. A permitted replacement inference is a new charged attempt, not recovery of the old answer.

### 6.3 Apply useful proposals

Accept model-proposed memory revisions, relations and procedures through a small application check: parseable result, addressed inputs/targets and relevant concurrent revisions. Models do not need a certificate of semantic understanding before a provisional note becomes usable. App-generated record IDs avoid confusing a proposed new item with an unrelated existing one.

Commit genuinely dependent changes together. Independent valid proposals may survive an explicitly partial batch. An explicit successful keep is allowed. A failed execution with diagnostic text, missing pages or an unparseable response is not keep and does not mark the episode interpreted. The original observations and unrelated work remain usable. Physical erasure, execution permissions and the user's goal are not inferred from prose.

### 6.4 Cost and observed support

Retain requested route/model separately from what the executor actually reports. Use known usage with its basis: a cumulative session snapshot is not another independent per-job charge, and a request's budget is not measured consumption. Unknown usage is not zero. Count actual retries and late results even when a stale proposal is no longer applied.

Text-only interpretation does not need code-editing tools merely because the selected executor is a coding harness. Use a route with the appropriate actual tool configuration; do not add a separate permission platform inside memory. Credentials stay outside model context. Demonstrate the chosen route's actual request, terminal response and readback behavior during implementation before calling it integrated; there is no requirement to qualify all providers before using one working route.

### 6.5 Embeddings are a separate batch operation

**Still missing as a verified callable interface:** the inspected controller public registry does not provide a dedicated vector-embedding method. The minimum required extension belongs to the existing controller's model/provider boundary, not to a new service inside Memory OS. Its public method name and selected native encoder are not asserted to exist in this revision.

The required data operation is small: a stable request key, encoder route and a batch of item IDs, content revisions and text in; corresponding vectors or item errors and the actual encoder/profile out. Where the encoder distinguishes query/document input, preserve that setting. A native positional response can be matched to the retained submitted order; never associate by an unrelated response order. Existing §4.2 checks finite values, dimensions and content/profile correspondence. A partial valid batch can be applied without discarding primary content.

Do not ask a generative agent to print plausible numbers, wrap each embedding in a coding Task, or select a second memory database to hide this missing capability. Reuse the controller's transport, provider configuration and actual request execution; a thin typed operation is sufficient. Text synthesis and vector generation use independent configured routes, so changing Dreamer does not re-embed the corpus. Exact/lexical capture and recall continue while this route is unavailable; the full vector-enabled product is not declared finished until it is connected.

### 6.6 Avoid a circular dependency between execution and memory

Controller-to-memory context and memory-to-controller synthesis are separate calls. A job already holding its saved episode can start interpretation without first waiting for the finished project view or lesson it is itself producing. Optional retrieval during that work reads available primary memory; it does not demand completion of its own job. This is ordinary call placement, not a new readiness graph or bypass token.

Eliot's `jobs` owns when a semantic transformation is useful; controller owns native execution. Do not add an autonomous controller Goal that repeatedly asks for the same memory job after it has completed. One final response supplies material to the existing memory transaction; indices and additional views can follow without a recursive controller-to-memory-to-controller startup loop.

## 7. Learning that reaches a subsequent attempt

### 7.1 Ordinary memory and outcomes

A procedure contains trigger, relevant conditions, behavior, evidence, exceptions and expected effect. Attempts reference the method actually offered/used and observed results. Aggregate estimates are views, not another learning database.

First path: a real API/consumer failure or useful success is captured; a method is extracted; a suitable advisory becomes eligible automatically; it is offered at a later decision; the resulting action/outcome improves or narrows the method. Existing historical evidence survives unrelated project changes. [Cognition §6.8](COGNITION.md#68-one-episode-to-a-useful-next-attempt) describes the producer and consumer.

The working interpretation is a normal controller request over saved episode material and relevant current lessons. Its result creates a lesson, amends a named lesson or keeps the existing content. Save that content in the same searchable memory used by `context` and `open`. Do not copy it into a separate skill registry or wait for a qualification pipeline. Listing/inspection reads those actual records; an empty store returns an empty list, not generated demonstration cards. Semantic checks and wider generalization can improve the lesson later without being prerequisites for its first qualified use.

### 7.2 Applicability, not a universal promotion barrier

Cognition distinguishes applicable, inapplicable and unknown. Missing preconditions are not filled by similarity. Unknown can still yield a conditional analogy or a useful check instead of total refusal.

Provisional reuse in another configured situation is automatic when appropriate; no approval or experiment per record. Claiming broad effectiveness is a stronger question requiring subsequent comparable evidence. Conditional usefulness does not depend on already proving a universal causal benefit.

For the API example, a missing diagnostic counts as success only when a suitable complete check covered the target revision. Distinguish a supported pass/failure from an inconclusive or unobserved check. Keep other real failures and costs visible; do not blame every offered procedure for an unrelated network problem.

### 7.3 No artificial accumulation of support

One current outcome contribution per method revision, attempt and criterion. Replay does not multiply it; a correction replaces it with history. Steps of one attempt, paraphrases and repeated summaries are not independent examples.

Separate delivery, observed action, adherence, outcome and comparative benefit. Induction examples did not benefit retroactively from a method invented afterward. A heuristic score may rank candidates without becoming a causal claim. For empirical comparisons, retain material task/model/tool conditions and actual exclusions; do not build a statistics service before useful local learning.

### 7.4 Recursive improvement from Harness2

Use [Cognition §6.7](COGNITION.md#67-two-recursive-loops-from-harness2): within a task, Propose–Probe–Compose changes a concrete method against observed contrasts; across tasks, retain lessons about how to diagnose and improve.

Keep baseline/no-change eligible. A composed output is not automatically better; previous task-specific instructions are not blindly inherited. Existing revisions, attempts, jobs and controller execute the loop. No separate recursion server, reflection database, per-level swarm or compulsory benchmark workload is required. Compare repeatable work/copies or permitted executions, not unrequested repetitions of irreversible effects.

### 7.5 Diagnose the failing step and revise the useful method

Capture a user correction, wrong-scope complaint, repeated failure or observed costly repetition as an ordinary observation. Associate the affected memory/context/attempt when that relationship is known; otherwise retain the report without inventing an attribution. Use the actual sources and available execution records to distinguish what failed. Do not require a complete system-wide measurement packet before examining one concrete problem.

| Observed problem | First useful inspection or change |
|---|---|
| Needed experience was never retained | Inspect capture/episode input; preserve missing material when available |
| The lesson exists but was not found | Inspect the actual query, cues and selected candidates; fix retrieval, not the lesson's factual support |
| It was found but did not reach the agent | Inspect packing, suppression and the real host boundary; correct delivery rather than re-extract every episode |
| It reached the agent but was not applied | Inspect wording, applicability and the known action; do not infer causality from delivery alone |
| It was applied and the relevant outcome worsened | Reconsider the method, conditions and criterion; amend or stop recommending the affected revision |

These are diagnostic distinctions, not five mandatory passes or a requirement for telemetry before every read. If a needed observation is unavailable, name that gap and still act on the independent facts that are available. A partial view must not declare the whole product healthy; it also must not hide a known failure because another dimension is unmeasured. A success and a failure in the same broad category are not a contradiction unless they concern incompatible claims under matching conditions.

A previous failed repair narrows the usefulness of that repair under its actual conditions. It does not disable diagnosis for the whole configuration. Do not issue the same unsupported intervention again merely to appear active. New observations, a different mechanism or a changed relevant input can justify further work without inventing a new configuration identity.

`learning` can propose a targeted memory or context-method revision using the existing Dreamer job. Direct corrections need no model; a missing retrieval connection may need ordinary code work rather than another generated lesson. Save the chosen revision, its reason and source observations through `apply`; use it provisionally where appropriate and inspect subsequent relevant outcomes. Preserve or restore a useful earlier method when a new one proves harmful, without erasing the failed attempt. Changing executable code, deployment, tool access or the owner's objective is not an implicit side effect of a memory proposal: route actual development/configuration work to the existing owner.

The loop finishes with a useful correction, an identified implementation defect, no worthwhile change or a specific unresolved question. It resumes on relevant new material or an explicit request, not every time its own diagnostic note is read. No separate self-quality database, global intelligence score, proof factory or mandatory replay campaign is introduced. [Audit §36](AUDIT.md#36-disagreement-research-and-self-revision-023) distinguishes these V3 choices from the inspected V2 decision tree.

## 8. Project understanding, causality and research

### 8.1 First useful orientation, not compulsory whole-project onboarding

Within configured memory/background settings, the first attachment makes a finite orientation job due automatically. Foreground capture and context return existing knowledge and available source facts immediately. The agent need not call an onboarding ritual, propose every concept or approve every view. The owner can correct the result afterward through ordinary memory edits.

Begin with actual project documentation/manifests and the area relevant to the task. Grow a compact purpose/map/area view as useful material becomes available. A directory grouping can help navigation without defining the real conceptual architecture. A file may serve several cross-cutting concerns; there is no required minimum number of concepts, unique file-to-concept partition or complete pyramid before the first helpful response. Non-code projects use their documents, sections, observations and sources through the same path.

### 8.2 One selected structural source, not an embedded code-intelligence platform

Use a configured **codebase-memory-mcp** connection as the initial structural adapter when available through the host/controller tool route. Source reviewed on 2026-10-21: [DeusData/codebase-memory-mcp at 3457b21b](https://github.com/DeusData/codebase-memory-mcp/tree/3457b21b0a3d75960c07ed3ec666a9e684985ef9), donor D47. Its [actual get_architecture handler](https://github.com/DeusData/codebase-memory-mcp/blob/3457b21b0a3d75960c07ed3ec666a9e684985ef9/src/mcp/mcp.c#L8059-L8290) provides compact languages/packages/entry-points by default and scoped requested aspects. Request structured output for adapter use rather than scrape display prose.

Use its documented `get_file_outline`, `search_graph`, `trace_path`, `get_code_snippet` and `check_index_coverage` for the particular question and source span. The inspected trace evidence distinguishes language-server resolution, language rules, heuristics and unresolved relationships. Retain the relevant origin/limits in the source observation; a static call is not an observed execution. The complete parser, every language and every tool path have not been qualified by this source review.

Reuse the existing tool's owner and index. Do not embed its C parser, copy its whole SQLite graph into SurrealDB, install its UI, reproduce its coordination daemon or rewrite the user's agent setup from a memory job. Its index is an external derived source; Eliot stores selected source observations, decisions, lessons and project views as its own memory. The first adapter is a narrow caller, not a universal code-graph abstraction.

If the configured graph is absent, unavailable or incomplete for a language, use existing scoped source reads and textual search plus manifests. State that these do not establish a complete call graph. Do not make raw capture, lesson recall or all project orientation wait for the index. Connecting the selected tool in the actual host remains implementation work, not an assertion that this session invoked it on Eliot.

### 8.3 Structure supplies evidence; Dreamer explains its meaning

A compact structural inventory selects where to read. Supply the relevant declaration/body, documentation and recorded decisions, or handles the executor can actually open, before asking for purpose, boundaries, material invariants and likely consequences. Counts, filenames and symbols alone do not establish why a subsystem exists. Exact structure, documented intent and inferred explanation remain distinguishable.

Save a useful explanation as an ordinary versioned view with its examined source scope and links. There is no rigid four-kilobyte input rule or fixed purpose-length limit for every project: size the request for its useful evidence, use progressive reading and render a compact answer. Missing rationale stays missing. If interpretation fails, retain the available structural facts and previous useful explanation; do not publish a generated `purpose="(pending)"` as completed semantic understanding. Valid source references and a complete heading skeleton are not proof that the explanation is correct.

Several perspectives can cover the same resource. A package map, an API-flow explanation and a deployment view need not share one forced tree. Use existing memory links for the selected relationships; do not mirror every source symbol just to draw a map. Git co-change may suggest another relevant file, but it is not a static dependency or a causal effect. Read available Git history selectively for a concrete question; mandatory full-history mining is not an onboarding prerequisite.

### 8.4 Refresh the affected view from actual source changes

Reuse actual host file events and the configured structural tool's status. For a Git workspace, native `git status --porcelain=v1 -z --untracked-files=all` distinguishes staged/unstaged, deleted, renamed and new paths; the [Git status contract](https://git-scm.com/docs/git-status) is the source for parsing, not human display text. Read relevant changed content or diffs when needed. HEAD alone does not describe a dirty worktree. Non-Git sources use the available event/listing and content information instead.

A changed cited file can dirty its views. A new consumer, changed manifest/configuration, rename, deletion or source-selection change can also affect a set-valued view without modifying its old citations. Apply the existing reverse source links and examined selection scope from Cognition §4; coalesce one pending refresh for that view. If the observation stream has a gap, reconcile the relevant area on reattachment or demand. Do not rescan the entire project before each read or build another general watcher/lineage service.

Provider coverage is useful but not a completeness certificate. The inspected CBM coverage output explicitly describes best-effort results, exclusions and truncation; `metadata_match` compares recorded file metadata, not full content equality or semantic truth. Read the relevant source when a consequential negative assertion needs more support. Unknown coverage does not make stored history unusable. Refresh a parent only after a material child result changes, not merely because a refresh timestamp changed.

### 8.5 Automatic work must have a useful output and consumer

Use the existing target-keyed jobs for initial orientation, a material source change, an explicit correction, a useful unresolved question or an observed episode needing interpretation. Prioritize changes relevant to active work and corrections; use otherwise available background capacity for useful incomplete areas. No model call is required for every filesystem event, every concept or every access. Unchanged input/no-change is reused; a model outage leaves work pending and does not stop reading. Work runs while the demand-start profile is active or on its next start, not through an unrequested permanent nightly service.

At the next supported planning boundary, `context` combines the relevant available view with actual constraints, applicable experience, dissent and the useful next check. An automatic refresh does not require the agent to discover and query its new ID. Avoid resending unchanged orientation; a material correction can be offered as a small update. Delivery remains different from use or improved outcome. The host/controller still owns the task and its execution.

Record a prediction only when it names a useful expected observation before an action; compare with the subsequent actual result when available. Static edges or a graph-derived answer key can check structural recall, not certify real-world causal understanding. Do not import a compulsory weekly exam or an automatic advice cutoff based on `injected_tokens - observed_exploration_tokens`: more observed exploration is a cost, not measured savings. Later comparisons can assess total work and outcomes without blocking current useful memory.

Research uses the same source-linked views and finite work. Keep examined scope, evidence, alternative explanations and open questions; a generated explanation does not silently rewrite the owner's goal or erase an inconvenient source. This preserves autonomous understanding and learning without a new concept server, permission stage or self-certification loop.

### 8.6 Resolve the question, not a compulsory panel

Represent a material disagreement with the existing claims/hypotheses and links, plus an ordinary question or decision item when it needs continuing attention. First compare subject, scope, time and perspective: a historical statement and a current correction, or a requirement and observed code, are not automatically two competing descriptions of the same thing. No separate ConflictRegistry or TheoryPortfolio store is required.

Read the strongest available grounds for each relevant explanation, including shared sources and counterevidence. Find the smallest useful discriminating observation: an exact source read, a known result, a targeted lookup or a suitable experiment through the actual executor. When a direct source already answers the question, do not convene models to restate it. Semantic comparison can use one finite Dreamer request; additional independent work is optional through the host/controller when it contributes different evidence or a genuinely useful challenge. Multiple answers from one model or copies of one source do not become independent observations by changing agent names.

The output contains the supported conclusion or qualified alternatives, the grounds that mattered and the remaining question when relevant. It need not fill a fixed number of rival slots. Save a provisional decision with its rationale and a material reconsideration condition; retain substantive dissent instead of rewriting all positions into agreement. Normal context delivers the conclusion and its exception together. A provisional external action remains the host's or user's decision, not a new authority issued by memory.

If the question remains unresolved, the independent part of the task and useful existing memory stay available. The related recommendation is conditional, or the missing check is shown; the whole project is not blocked. Stop the finite investigation when it has a supported answer, no informative next step, exhausted permitted work or unavailable required material. Relevant new evidence can make another job useful. Unchanged opinions alone do not start another automatic debate.

### 8.7 Acquire the missing evidence through an actual research route

The trigger is a useful question left unresolved by existing memory and selected local sources, not every empty field. Identify what observation would change the answer and first use the available source/tool that can supply it. A routine source lookup does not require deep research or a critic panel. More extensive acquisition belongs to the configured external Research system, not an embedded web crawler, corpus index or research workflow inside Memory OS.

The separate [Eliot Research project](https://github.com/UnknownAlienHuman/eliot-research/tree/7c034569b908d3b03a8b821b7c537477a24b10f7) is itself being simplified. Its [current implementation plan](https://github.com/UnknownAlienHuman/eliot-research/blob/7c034569b908d3b03a8b821b7c537477a24b10f7/docs/implementation/backend-entrypoints.md) distinguishes an ordinary answer from explicit deep research and replaces old report-admission machinery. This pass read that plan, not the complete live federation endpoint. The exact callable request/result adapter therefore remains an implementation choice; no new RPC name or completed integration is asserted here. Do not recreate V2's generation/digest/freeze protocol merely because old contracts in both repositories mention it.

Use the existing memory job and the configured route. Supply the concrete question, scope/time/version when relevant, chosen source classes and only material intended for that external route. Retain the actual external request reference and the returned source/report references. Question, source observations and synthesis remain distinguishable. An answer with citations is not automatically a verified procedure; a failed acquisition is not a negative research finding. If only a report or snippet was read, record that coverage instead of claiming inspection of the full underlying source.

Keep compact useful source excerpts, decisions, hypotheses and lessons in ordinary Eliot records. Large external corpora and their parsing/indexing remain with the research owner and are opened by source handle when needed; do not replicate both databases or give Research a direct writer into memory. Existing local observations remain primary input, not disposable merely because an external copy was requested. Useful partial material can enter context with its limits while another source is unavailable.

Apply the returned knowledge using the same memory/history/link transaction, then surface it through normal context or the continuing inquiry. Retain an unresolved point when the material is insufficient. A provider failure may be retried through its existing execution path; completed but uninformative research instead needs new evidence, a changed useful question or an explicit re-evaluation—not automatic repetition of the same request. Ordinary saved observations and last useful answers remain readable throughout.

## 9. Control, supervision and completion

### 9.1 One actual independent observer

Reuse working external supervision or use the standalone supervisor mode. Own process handles and the actual daemon/database family; process-name matching is not custody. Observe service-path progress separately from the worker, distinguish planned idle shutdown from failure, and avoid ineffective restart loops.

Use standard [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects), not per-poll binary attestations. The observer has no semantic database/provider queue. Concrete Windows launch and hang behavior is verified during implementation, not assumed from this document.

### 9.2 Monitoring and notification

Use available host/source events to show progress and observation gaps. Heartbeat, a file change, a notification and actual task completion are different. CLI status/inbox reads the same state; UI can be added as a view.

Deduplicate by problem and material change. Optional logging/channel failure cannot prevent reading status or recording an acknowledgement. Mechanical recovery may restart owned work or rebuild an index, not rewrite meaning to make a check pass.

### 9.3 Honest completion

Memory records outcomes; the host/controller and user own external task acceptance. Show what was checked and what remains unknown. One local verifier covers its own criterion. No mandatory finish ritual or proof object is required for every interaction.

### 9.4 Direct local control and attention recurrence

Direct local control addresses the actual target and operation. Readback, acknowledgement, pause and cancellation of owned work do not depend on models, toast binaries or a Critical-action approval producer. Report actual storage/executor failures; a cancellation request is not proof that the external effect stopped.

Within the same attention record, distinguish stable problem, observed event, episode and displayed revision. Repeated polls are not new incidents. New evidence updates a problem; a real later recurrence can reopen it. Acknowledgement covers the material the person saw, not every future episode. Dismissal is not proof of technical recovery.

Update current state and retain necessary history in one transaction. Do not replay and rewrite its entire history or revalidate old receipts before each acknowledgement. History is queried when needed; recovery is not the ordinary update path.

## 10. Deletion, backup and restore

### 10.1 Defined deletion

Keep the minimum deletion/replay information needed outside rollback-prone backups. An ordinary append-only file of affected source IDs or scope and sequence is enough; not deleted text, a signed chain or a second semantic store.

Order known withdrawal against replay/publication and acknowledge what actually happened. Remove controlled primary/derived data, indexes, blobs, caches and affected copies as needed; distinguish logical withdrawal from completed physical cleanup. A private synthesis does not become public by unlinking one citation. Already disclosed host/provider copies are outside this local guarantee.

### 10.2 A concrete backup

Pause primary mutations and new external dispatch, let short transactions finish without holding their lock, then seal a finite spool cutoff and open a fresh batch. Export stable primary data with its referenced blobs, included staged input and available deletion information into a temporary backup directory.

New input remains in the fresh batch outside that cutoff. Duplicate inclusion of an already committed event is handled by normal event identity. Publish a completed-backup marker only after its required components are saved. Checksums concern actual copy integrity. Interrupted exports are not complete backups.

This initial design pays an export-length write pause rather than inventing an instantaneous snapshot. Status and cancellation remain responsive. A conflicting erase can cancel backup or remain explicitly pending, not falsely applied. [Backup reference](https://surrealdb.com/docs/manage/self-hosted/backups-and-recovery).

### 10.3 Restore usable data, not an unattainable proof

Restore the selected backup into a fresh directory, apply known current deletions and verify that primary data can be read. Make recovered primary memory available without waiting for embeddings, project maps, historical telemetry or every old job to reconcile. Rebuild derived data separately. Missing optional derived files do not invalidate intact primary content; identify actual missing primary portions instead of fabricating them.

When the owner explicitly restores a chosen copy and the current deletion journal was lost, report that earlier erasures cannot be fully reconstructed and allow recovery of that chosen data. Do not require a new selective-import workflow or keep the whole copy indefinitely quarantined because independent historical metadata no longer exists. Apply whatever known restrictions remain and retain the owner's configured disclosure choices. This cannot promise unknown past deletions were preserved.

Restoring data does not automatically restart old external jobs. A pending request in the backup may already have executed; reconcile it separately before another external action. This limits replay of effects, not the owner's access to recovered memory. Keep application semantic revisions in ordinary records and check actual import failures.

### 10.4 Simple upgrades

Use one current schema and supported application/server range, a completed backup, and explicit resumable migration steps where required. Do not open a genuinely incompatible format by ignoring it. No hot-generation matrix, permanent dual-format facade or full V2 runtime compatibility is required; old data import is a chosen conversion.

## 11. Work sequence

This task remains documentation before the rewrite. [AUDIT-MAP](AUDIT-MAP.md) tracks remaining source reading, not implementation permissions. Once implementation starts, build connected behavior rather than all DTOs, then all mocks, then a future integration project.

### 11.1 Use the component that already owns the operation

| Need | Direct implementation | Machinery not required |
|---|---|---|
| Remember a tool result | Host event → capture → the original saved observation | Fabricated execution proof, second executor or a model inferring whether the tool ran |
| List/open a learned method | Query its actual stored record and content | Template-card factory, separate skill registry or proof needed to read advice |
| Deduplicate an observed event | Existing source identity as record key or a native unique index; short DB transaction | Hashed admission plan and process-wide coordination service |
| Search and publish memory | Native full-text/vector indexes; commit related primary changes together | Mirrored search database with its own publication and recovery protocol |
| Interpret an episode | Existing due job → real controller call → create/update/keep ordinary memory | Mandatory maturity ladder, second model scheduler or success-shaped stub |
| Show status/history | Read the same saved events and job state | Reports that become another authoritative mutable database |

The native index and transaction choices are supported by [SurrealDB index documentation](https://surrealdb.com/docs/reference/query-language/statements/define/indexes) and [transaction guidance](https://surrealdb.com/docs/learn/querying/concepts-and-guides/transactions), consulted 2026-10-20. Database uniqueness handles concurrent storage conflicts, not exactly-once external provider execution. Keep that distinction without introducing another platform. Native capabilities still need concrete domain queries and small adapters; avoiding scaffolding is not pretending application logic disappears.

### 11.2 Build a working path, then extend it

Start with actual capture into the selected SurrealDB instance and retrieval of that same content after restart. Add the host's real event and context boundaries so another interaction can receive that memory. Then connect one real controller route to an episode transformation and make its saved lesson appear through the same context/open path. These are successive useful product capabilities, not a new certification workflow. Richer cognition, vectors, recursive improvement, additional adapters and the remaining recovery requirements complete the same product; the first path does not redefine the full scope.

Cheap deterministic work stays in ordinary functions. Persist only work that actually continues later or across failure. Use a narrow adapter for a real host/provider difference; do not design a generic plugin, query or workflow framework around one implementation. A new control is warranted by a specific real failure, not by an invented prerequisite of another control.

An unconnected capability remains unfinished and returns its actual local limitation. Do not replace missing database/model/host behavior with generated cards, successful outcomes or a production branch selected by a test fixture. Other connected functions continue. Demonstration data belongs outside ordinary user data and cannot be evidence of product execution.

Follow the owner's sequence: product code, minimum relevant checks/Clippy, tests after the product is built. Later tests exercise the same production entrypoints and real domain behavior; fixtures may replace an external boundary in those tests, not establish a second implementation inside the product. A false expectation should be corrected, not satisfied by weakening the feature or manufacturing a result. No new test suite, mock platform or acceptance-report generator is part of this documentation change.

## 12. End-to-end scenarios for the future product

| ID | Situation | Required observable result |
|---|---|---|
| S1 | Unknown note type; model absent; duplicate delivery | One preserved observation and exact read without invented classification |
| S2 | Resume, compaction or non-Git source | Goal, alternatives, commitments and next step reconstructed; missing anchors shown |
| S3 | Familiar resource before an action | Advice reaches a relevant model decision; optional host enforcement stays separate |
| S4 | Contradiction, false synthesis or poisoning | History/dissent retained; affected influence corrected without disabling unrelated memory |
| S5 | Missed file-change event | Affected current views refreshed, unrelated history retained |
| S6 | Prediction before an edit | Named effect compared under matching conditions; correlation remains distinct |
| S7 | Similar error under other conditions | Applicability checked; similarity alone does not block |
| S8 | Method learned from success/failure | Subsequent attempt linked; delivery, action, outcome and benefit distinguished |
| S9 | Harmful transfer | Counterexample retained; affected use narrowed without rewriting old outcomes |
| S10 | Model change, malformed output or foreign target | Invalid transformation isolated; original memory and other routes continue |
| S11 | Incomplete research or absent provider | Useful available material plus scope/gaps; no universal conclusion from empty top-k |
| S12 | Database outage, lost reply or expired worker | Preservation states distinct; stable readback; old claim cannot publish |
| S13 | Service hang | Actual independent observer detects owned failure and performs bounded recovery |
| S14 | Forget, erase and restore | Exposure, influence and purge separate; known current deletions are applied |
| S15 | Partial result or absent verifier | Criteria/unknowns reported; one local pass does not become whole-task success |
| S16 | Large audit and dissent | Unique coverage, source links and discriminating alternatives preserved |
| S17 | False enforcement | Optional false trigger can be removed without breaking normal memory use |
| S18 | Optional failure, pressure, repeated repair | Useful control/read/capture retained; ineffective retries stop visibly |
| S19 | Unreported changes, missed alert or unknown executable | Gaps surfaced; acknowledgement not resolution; no unrequested executable probe |
| S20 | Host/model/tool profile changes | Applicability checked without erasing historical experience |
| S21 | Worker restart after external acceptance | Same execution read back, not another inference caused by a new claim |
| S22 | Replayed/corrected feedback | One current contribution per attempt/criterion |
| S23 | Reordered, short or incompatible vector batch | No silent vector misassignment; intact primary records stay usable |
| S24 | Interrupted backup while capture continues | Incomplete copy identified; post-cutoff input remains in fresh spool |
| S25 | Restored data with old jobs or missing deletion history | Owner-chosen primary recovery remains available; disclose history gap and reconcile effects separately |
| S26 | Host replays old injected advice | Current applicability clarified; no remote-erasure promise |
| S27 | Valid local acknowledgement/cancel while optional approval infrastructure is absent | Operation-specific control still reaches its owner or reports actual storage/executor failure |
| S28 | A resolved problem recurs before an old acknowledgement arrives | A new episode remains actionable; the stale acknowledgement cannot silence it |
| S29 | A successful primary tool is followed by an enrichment/logging failure | Preserve the known primary result and the observation gap; do not imply the effect never ran |
| S30 | Process stops after preparing advice but before transport handoff | No permanent delivered claim or suppression from a prepared-only observation |
| S31 | Same spelling denotes case-distinct symbols or different path roots | Exact identity remains distinct; broad aliases stay advisory |
| S32 | A small cue result needs source text from a large project | Hydrate selected IDs and necessary alternatives, not the whole project payload set |

All [29 original A15 scenarios](AUDIT.md#12-all-29-original-scenarios) and S1–S32 remain represented. The restored-data scenario now explicitly removes the blanket quarantine requirement. [Cognition §8](COGNITION.md#8-implementation-placement-and-future-walkthroughs) retains the cognitive/recursive examples; no new checklist family is added.

## 13. Remaining concrete integration choices

| ID | Direction | Remaining implementation choice |
|---|---|---|
| O1 | Native Claude hooks + MCP | Installed event/ID and continuation/result behavior |
| O2 | Existing controller; concrete synthesis Task/result mapping in §6 | Connect one selected route end to end; implement the missing dedicated batch-vector capability in the controller owner, with actual model and readback behavior |
| O3 | Small spool and ordinary backup/restore | Windows file primitives and concrete recovery behavior |
| O4 | Official network SDK and primary native indexes; initial layout/operations in §§2.6–2.9 | Implement actual DDL, typed bindings and parameterized mutations for the selected profile; inspect plans and observe behavior on that build |
| O5 | Automatic provisional learning and transfer | Useful task criteria and evidence for broader benefit claims; targeted self-revision follows §7.5 |
| O6 | Reused or small independent supervisor | Actual process custody/progress and notification coverage |

The external Research adapter in §8.7 also needs a concrete callable request/result mapping during implementation; reading its refactoring plan is not that integration. These are implementation choices, not admission gates for unrelated functions. Use the working path, isolate an unavailable extension, and report the actual limitation.
