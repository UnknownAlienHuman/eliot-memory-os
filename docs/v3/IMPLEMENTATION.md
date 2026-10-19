# Eliot Memory OS V3 — Implementation

**Revision 0.6 · 2026-10-19 · technical design; no V3 runtime or query has been qualified.**

[Architecture](ARCHITECTURE.md) defines the product. [Cognition](COGNITION.md) owns the algorithms for resolving claims, project understanding, transfer and recursive improvement. [Audit](AUDIT.md) separates source findings, proposals and unverified behavior. [Audit map](AUDIT-MAP.md) tracks remaining work. This revision removes inherited donor vetoes and unnecessary control machinery; it does not change V2 code, CI or user data.

## 1. Initial delivery

### 1.1 Runtime and module shape

Start with one Rust package, an executable with service/CLI/relay modes, and ordinary modules. A new crate requires an actual dependency, deployment or change boundary, not a named concept.

| Module | Owns | Does not recreate |
|---|---|---|
| `store` | Schema, fixed parameterized queries, transactions and mutation readback | A query language, storage bridge process or semantic mirror |
| `memory` | Capture, semantic revisions, source links and correction | External task acceptance or provider execution |
| `context` | Independent retrieval arms, applicability and packet assembly | Another source of semantic truth |
| `learning` | Procedures, improvement lessons and outcome reduction | An overlay store, promotion service or second scheduler |
| `jobs` | Finite memory work, claims and conditional result application | Controller provider-attempt state |
| `adapters` | Real host, source and controller interfaces | Capabilities inferred from similar names |
| `control` | Configuration, maintenance, status and recovery | An enterprise authorization platform or replacement OS |

SurrealDB is the server child of `eliotd`; only the private Store performs application writes. Use its native lexical/vector indexes, relations and transactions. Do not add redb/SQLite for semantic state, a named-operation catalogue, a generic query AST or compatibility facades.

The first target is local Windows. Independent observation must exist while the observed profile is active. Reuse a host/controller supervisor only when it actually supervises Eliot's process and failures. Otherwise the same binary has a small demand-start supervisor mode owning daemon plus database. That standalone profile has three owned processes, not one; external controller/model processes are additional. The relay is transient. Do not build both supervisors for the same process tree.

### 1.2 Demand-start and graceful loss of capabilities

One OS single-instance boundary per data directory serializes startup. Local readiness means storage and required local functions work, not that every model route is available. Capture and exact/lexical retrieval remain useful without generative inference. Vector capability remains part of the full product, with an explicit degraded route when unavailable.

Idle shutdown stops admission of new external work, settles short mutations, retains pending work and stops the owned database. Intentional shutdown does not trigger a restart storm. No SCM installation or OS scheduled wake is part of the default. Due work runs while active or on the next demand start; show overdue work instead of pretending it ran. A separately enabled wake does not become another scheduler.

### 1.3 One database client, without a donor veto

Use the official network-capable Rust SDK as the initial V3 client choice, private to Store. Select one compatible SDK/server release and only the required network/TLS features when implementation starts. Do not compile embedded engines into the production client without a need. The exact versions and dependency graph remain unqualified here.

The old [Phase A ADR](../ADR/0001-phase-a-dependency-boundaries.md) recorded a then-current transitive dependency/release-gate problem. V2 is a donor: this ADR does not require a new permission ceremony before V3 may use the SDK. Nor does this design claim that an old vulnerability persists or has been fixed. A real unresolved dependency, platform or size problem may justify a narrow official JSON-RPC client instead; document that concrete reason and use one client, not both.

Transport success is not a successful transaction. Check every statement result, required bindings and the expected number of changed rows. A conditional one-row update returning zero rows did not publish. The [SDK query reference](https://surrealdb.com/docs/reference/rust/methods/query) exposes statement errors and notes that an unbound parameter becomes `NONE`. These are a few checks beside fixed queries, not a SQL-validation language or a signed query manifest.

## 2. Minimal data and ownership

### 2.1 Record families

| Family | Necessary information |
|---|---|
| Observation | Stable source event/revision, original permitted content or blob reference, scope, time and capture limits |
| Memory revision | Claim, decision, procedure, failure, unknown or project view; content, source references, applicability and current exposure |
| Link | Evidence, required live anchor, contradiction, replacement or structural/navigation relation |
| Attempt/outcome | Actual host task when known, delivered method revision, observed action, criterion and its result/coverage |
| Job | One finite transformation, input/method identity, due state, current claim, external request reference and result |

These are logical families, not an order to produce exactly five tables. Keep mutation readback beside the relevant observation/job/transition when possible. Add a small operation record only when a real acknowledged mutation cannot otherwise be found by its stable identity. Do not put every read, notification and pure helper through a second generic Operation state machine.

Semantic history consists of actual application revisions, not overwritten rows with an assumed engine undo log. Persist large permitted blob bytes before publishing their database reference; remove unreferenced leftovers later. An extractor's short prompt is not permission to silently discard the original exception. If capture kept only a prefix/tail or external handle, state that limit. Backup and deletion include blobs.

### 2.2 Source identity, time and state

Bind a session to the configured local project/workspace; a model does not supply authoritative owner or foreign write scope. Branch, resource and tool version are applicability dimensions where relevant. Do not confuse an uncommitted worktree with its committed HEAD.

Replay uses the same source event/revision or adapter-assigned delivery ID. Same ID with different content is a conflict. Independent identical events remain distinct; copies of one event are not independent evidence. Preserve original spelling and derive a comparison key separately. Capture and query use the same normalization function, not two adapters with subtly different rules.

Keep occurrence time, receipt time and a claim's validity interval separate. Unknown time is not insertion time. Current-state comparison also distinguishes intended behavior, observed behavior and proposed explanation, as specified in Cognition.

Support, ordinary exposure and allowed influence are different dimensions. A hypothesis may be useful with its label. A quarantined or handle-only record is not permitted content merely because its influence is not equal to `none`. Use a small explicit selection rule, not dozens of combinations of lifecycle enums.

### 2.3 Historical evidence, live requirements and local disclosure

Historical evidence explains what happened at X; a live requirement establishes whether a concrete statement applies at Y. An unrelated source update does not revoke history. Required premises, independent alternative justifications and mere supporting citations are different. Removing an actual premise requires review or a new derivation; deleting its citation from unchanged text is insufficient.

Use the existing typed links, not a second truth-maintenance engine. Validate relevant selected dependencies, cache repeated checks within the request and refresh affected views in background. A limit or unresolved cycle cannot be reported as complete validity. Do not perform an all-corpus recursive walk before every ordinary read.

For the initial local profile, configuration selects projects, capture exclusions, retention and allowed local/remote routes. No user/organization/principal hierarchy, grant graph or per-record policy certificate is required. Group model inputs that share compatible disclosure rules; a local-only input makes its derivative local-only until regenerated from a permitted set. Do not build a general information-flow calculus to express this rule.

Source links remain necessary for correction and defined deletion. Model-supplied citations do not declassify material provided in the request. Check disclosure once when actually handing bytes to the external route, and recheck queued work before it is sent. The app's short write boundary orders restriction changes against publication; no database transaction waits for the provider. Already handed-off bytes and old host transcripts cannot be recalled by a local flag.

### 2.4 Hashes and checks only where they do work

Stable IDs and equality/revision checks handle ordinary retries and concurrent updates. A fingerprint may identify actual immutable payloads, cache inputs or backup components. Use a standard library, not a custom digest implementation. A hash is not authentication, semantic validity or proof that an agent understood a document.

Do not copy V2's policy/manifest/request/result digest closure around an in-process cue normalization or notification update. No signed read receipts, contract-set hash matrices, authority epochs or proof-of-comprehension objects enter this local profile. Real OS/file permissions, database credentials and configured external tool permissions remain in force.

The profile assumes cooperative adapters and actual host tool restrictions. An unrestricted process under the same OS account can access that user's files or administrative CLI; a `human_only` flag cannot make it a sandbox. State the limitation rather than invent an ineffective security subsystem.

## 3. Host interface and experience intake

### 3.1 Small application surface

| Operation | Purpose |
|---|---|
| `attach` | Bind a workspace and report the host's actual capabilities |
| `capture` | Preserve an identified event; return committed, staged, unknown or rejected |
| `context` | Assemble a packet for the current goal/decision cue and budget |
| `open` | Expand an accessible handle/revision or return its unavailability |
| `record_outcome` | Retain an observed result and eligible subsequent learning work |
| `dream` | Ask a question or request finite memory/improvement work |
| `control` | Inspect, pause/cancel, configure, correct or erase defined memory |

CLI, MCP and hooks reuse these functions. An internal helper is not automatically another MCP tool. Do not force agents to attach repeatedly, administer claims or fill evidence forms. An ambiguous project stays in a narrow session scope rather than a guessed foreign project. Non-Git sources use the anchors actually available.

### 3.2 Capture, correction and deferred input

Validate permitted storage, envelope shape and size, not semantic classification. One transaction reconciles stable identity, preserves the observation, creates necessary deferred work and retains enough result information for readback. A replay does not create a second observation or paid job. A correction retains the original identity and amendment rather than inventing another independent event.

When the database is unavailable or mutations are paused, use a small file spool for delivery only. Publish one complete bounded event file under a stable opaque ID. Concurrent relays do not append interleaved JSON to one line. Persist a temporary file and atomically publish it under a short ingress lock; a staged acknowledgement follows durable publication. Select and verify the exact Windows primitives during implementation, not by assuming `flush()` implies durable publication.

An active directory and sealed directories support backup cutoff. Prepare temporary files outside the directory that can be rotated; publish into the current active directory under the same short lock. Recover every sealed batch after restart. Enforce actual byte/item limits; disk-full is an explicit error. Remove an event only after primary commit or authoritative deletion. Staged input is not searchable confirmed memory.

Replay calls normal capture with the same identity and current restrictions. A lost response is read back before a new insertion. Use the single backup/deletion procedure in §10; never wait for a replay worker while holding the lock it needs.

### 3.3 First host and actual timing

Native Claude Code hooks plus MCP are the first proposed integration. Record the installed version and enabled events; official documentation is not an installed-machine test. SessionStart/UserPromptSubmit can supply orientation at the next planning boundary; tool results/failures feed capture; compaction/resume refreshes context.

The [hook reference](https://code.claude.com/docs/en/hooks#add-context-for-claude) says tool-hook `additionalContext` is read on the next model request. PreToolUse advice therefore does not necessarily change the already chosen call. An explicitly configured exact pending-action gate is separate. Never block every tool to create another opportunity for advice. A timeout in optional advice is degraded delivery, not a new permission decision.

Use real event/call IDs where available; out-of-order results must not be paired with the latest timestamp. An adapter can assign a stable delivery ID without pretending it knows an unavailable action correlation. A crash before a hook executes is not captured work.

On continuation, reconstruct goal, discarded approaches, commitments and applicability. A new context incarnation resets delivery suppression; an old delivered revision does not suppress a correction forever. Old inserted text may still exist in the transcript. No mandatory lesson or `finish` ritual is required on every Stop.

### 3.4 Capability limits

Capture, advisory timing, tool denial, outcome observation, transcript refresh and cancellation are separate capabilities. A search-only host remains useful without demonstrating the complete loop. Native hooks and a controller's SDK metadata bridge are different surfaces; similar JSON fields do not prove identical timing or coverage. Hostless maintenance completes a memory transformation, not an invented coding task.

## 4. Retrieval and context

### 4.1 Independent candidates and truthful resolution

Exact identifiers and lexical search query eligible primary records independently of vector candidates. Union their IDs with compatible vector results before fusion; a lexical-only hit does not need a dense threshold. Current alternatives and replacements are resolved by their indexed claim group, not just the top semantic hits. Use the `resolve_current` rules in Cognition.

Preserve useful exact source values in searchable fields/cues, with a handle to their context. A value hidden only in details must not become findable solely after an unrelated summary was found. Permit bounded source-neighborhood/raw lookup where needed; do not embed every raw log or claim universal absence from an unindexed portion.

Limit each arm by relevant project, state and influence before exposing content. Use native filtered vector plans where supported; examine the actual server/query plan before implementing a workaround. Small scoped exact vector search is legitimate. A filtered ANN result still does not prove complete recall. [Similarity search](https://surrealdb.com/docs/learn/data-models/vector-search/similarity-search).

### 4.2 Embedding identity and failure

An embedding belongs to its encoder/profile, dimension, preprocessing and content revision. Equal dimensions alone do not make two spaces compatible. A Dreamer model change does not require re-embedding source memory unless the encoder or embedded content changed.

A batch response must match item IDs or the documented exact ordering, count, dimensions and numerical validity. Missing, duplicate, reordered or incompatible items cannot silently receive another item's vector or a zero-vector success. Apply valid independent items only with explicit partial status. A failed embedding leaves the source preserved and lexical lookup usable.

Changing encoders builds a separate compatible index/profile and switches queries coherently; do not mix old document vectors with a new query encoder. A local/cached query vector or separate asynchronous request can serve the fast path. Remote embedding is still a paid network call and need not block a synchronous hook.

### 4.3 Pack a decision, not independent snippets

Select goal/criteria, applicable constraints, relevant current state and experience, qualifications, missing information and the next useful check. Empty sections add no text. Keep a claim with its material exception or counterevidence; do not drop the exception to satisfy a record-count limit. Use handles for progressive reveal, rechecking current scope and availability.

Track injected bytes/tokens and repeated expansion/reconstruction work alongside useful outcomes. A shorter initial packet may be more expensive when repeatedly resent in a host transcript. Retrieval does not strengthen a record merely because it is frequent.

## 5. Finite jobs and external execution

### 5.1 Keep the necessary identities, not duplicate state machines

A job stores purpose, input/method identity, due state, claim, limits, optional external request reference and application result. Local claim, external execution and memory result are different facts, but do not each require a standalone manager.

| Identity | Meaning |
|---|---|
| Job/input key | One memory-processing intention, not every wakeup |
| Current claim | Which local worker may publish now |
| External request reference | Which already dispatched model/tool execution to reconcile |
| Mutation result identity | Which database change was applied |

States may be pending, running, waiting, completed, failed or cancelled with a reason. Do not add a separate state for every diagnostic sentence.

### 5.2 Execute outside a short transaction

Claim eligible work conditionally in the database. Inspect a retained external request before buying new work. Perform computation outside the write transaction. Then recheck current claim, relevant input/target revisions and restrictions and atomically apply the result and complete the job. Zero changed rows or a conflicting commit means no publication.

A heartbeat only extends the matching unexpired claim; an expired worker cannot publish before another worker happens to reclaim it. Cancellation and completion contend on the same job row. Record a rejected late result outside the transaction that rolled it back when the explanation is useful. Use database time for lease conditions.

New events coalesce into a finite pending successor instead of continually cancelling paid running work. Reuse a completed no-change decision on unchanged inputs/method. An invalid output or unavailable provider is not no-change.

### 5.3 Retry is not another inference by default

Persist external request identity and immutable inputs before dispatch. Lost acknowledgement stays unknown until readback through that identity. A new local worker first loads it. Only controller owns provider-attempt selection and retries; Eliot must not race another provider retry independently.

If a route lacks durable readback or idempotent submission, expose the limitation. A separately permitted pure inference retry can cost again and is recorded as a new execution. Unknown external side effects are not blindly replayed. Local idempotent application does not prove one provider charge. Late usage and uncertain cost remain recorded even when the content cannot be used.

### 5.4 One enqueue and wake path

Insert required jobs with the corresponding memory transaction. Poll due rows with bounded concurrency; notifications only accelerate wakeup. A database event is an alternative enqueue implementation, not a second scheduler. A changefeed is not an infinite queue. Bulk import explicitly reconciles necessary derived work instead of assuming table events rerun.

Reserve service for foreground capture/control and prevent bulk embeddings from starving outcome intake. Capacity is derived from actual jobs/executions; no mirrored capacity ledger is required.

## 6. Dreamer through controller

### 6.1 Verified source boundary, not invented RPCs

The examined controller [integration document at 96a0d5a](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/96a0d5a6632cfbd541e804d7969d3e76e716bf6a/docs/eliot-memory-os-integration.md) describes requested controller-to-memory context, not an implemented reverse inference API. Earlier generic Operation code also separates lifecycle from semantic result. This is a limited source finding, not a fresh exhaustive search of the current controller.

Use existing controller execution infrastructure. Text generation and embeddings are independently available capabilities; precise methods and first supported routes remain an integration choice, not names invented by this document.

### 6.2 Small request/result boundary

A request needs stable identity, finite input/item IDs and content, method/output contract, selected route and relevant disclosure/cost limits. A memory job reference is enough for maintenance unless the actual executor requires a legitimate synthesis Task. Do not create fake coding goals to satisfy a transport form.

The result identifies that execution, output or partial/failure state, observed model/profile when available, usage or unknown usage, and readback/cancellation limits. Accepted input, completed inference and accepted external task remain different.

For text-only maintenance, avoid unnecessary workspace mutation tools. A route unable to provide this is not silently described as a pure inference endpoint. Credentials stay in controller, not memory prompts. A JSON budget does not technically constrain an independently privileged remote executor.

### 6.3 Apply proposals without a certificate factory

A model can propose a new memory revision, relationship, procedure or changed exposure. Check result shape/size, actual candidate/target membership, current revisions and job before applying it. New IDs come from the app. Subject resolution remains fallible semantic interpretation; shape validation is not proof of truth.

Interdependent changes commit together; independent valid proposals may survive an explicitly partial batch. A successful empty result means no proposal. Invalid JSON, missing source and unavailable route remain different. Physical erasure, user goals, acceptance criteria and execution permissions are not implied model operations.

### 6.4 Cost and qualification

Bound expensive work by the actual configured executor and account for all attempts. Unknown usage is not zero; retain the reservation/uncertainty until reconciled or handled under the chosen budget policy. Fallback does not expand disclosure or spending silently.

Before claiming a route works, observe its real request/result, errors, identity/readback, declared cancellation and usage behavior. That statement applies to the capability being claimed, not a demand to qualify every provider before using one working route. This documentation change makes no live inference claim.

## 7. Learning that reaches a subsequent attempt

### 7.1 Ordinary memory and outcomes

A procedure stores trigger, relevant conditions, proposed behavior, evidence, exceptions and expected observation. Attempts reference exact procedure/context revisions and available results. An aggregate is a view of outcome contributions, not another LearningState database. No hidden reasoning transcript is required.

First path: capture a real API/consumer failure or nontrivial success; create a local method; make a suitable advisory eligible automatically; deliver it at a relevant planning boundary; capture a subsequent action/result; retain, narrow or withdraw the method using new evidence. Original experience survives unrelated source changes.

### 7.2 Applicability is not a universal promotion test

Cognition defines applicable, inapplicable and unknown. Similarity finds candidates; it does not make missing preconditions true. Unknown may yield a conditional analogy or the useful missing check. It need not block all learning.

Automatic provisional reuse is allowed in another configured scope when material conditions and disclosure permit it. It does not require an independent experiment or approval for every record. Separately, a claim that the method is reliably better across situations requires suitable subsequent comparisons and negative cases. The 0.3 table conflated these two questions; it is replaced by this rule.

For an API-compatibility criterion, a missing diagnostic is not success unless the relevant check actually covered that consumer/revision and returned sufficient output. Preserve supported pass, supported failure, inconclusive attempted check and unobserved check separately. An unrelated network failure does not refute every delivered method; another real failure is not hidden by success on the selected criterion.

### 7.3 Unique evidence, not accumulated applause

One current contribution per procedure revision, attempt and criterion/evaluator revision. Replayed feedback does not increase support; an amendment replaces the contribution with its history. Steps within one attempt, repeated exports and paraphrases are not independent trials.

Distinguish offered, delivered, action observed, adherence, outcome and comparative benefit. Induction examples explain why a procedure exists; they cannot retroactively have benefited from it. Similarity, model confidence and a prior-adjusted score may rank hypotheses but are not measured causal improvement.

Keep infrastructure failures and costs visible. State which cases a quality comparison excludes and why. For empirical claims, compare fixed relevant criteria under comparable task/model/tool conditions and retain held-out cases. No generic statistics service or mandatory A/B before every provisional suggestion is required.

### 7.4 Recursive improvement from Harness2

Use the two loops in [Cognition §6.7](COGNITION.md#67-two-recursive-loops-from-harness2). Task-local Propose–Probe–Compose changes a concrete method against observable execution contrasts. Cross-task reflection retains lessons about how to diagnose and improve, alongside the chosen method revision and evidence.

The baseline/no-change remains eligible. A composed candidate is not automatically better or transferable. Keep the improvement recipe fixed within a comparison, then update its reusable lessons afterward. Do not inherit a task-specific harness wholesale. Early no-change can end useful work; the donor's fixed 4k/3k benchmark counts are not production obligations.

Use existing memory revisions, attempt links, controller execution and finite jobs. No separate recursion server, per-level agent swarm, new experience database or self-editing runtime is required. Optional expensive probes apply to repeatable work/copies or permitted real executions; do not rerun irreversible external actions merely to obtain a comparison.

## 8. Project understanding, causality and research

Cognition owns small purpose/map/area views, exact source structure, inferred meaning, selection-membership tracking and target-keyed refresh. A new consumer can change a complete-set claim without changing old citations. Exact capture and useful readback start before semantic onboarding of the whole repository.

Use existing host tools, ripgrep or one relevant structural/LSP/SCIP adapter. Do not embed several competing code graphs. Preserve intermediate edits when observable; a final diff cannot reconstruct reverted attempts. Reveal related history on demand.

Static dependency, co-change, analogy and causal explanation are different. A prediction precedes the action and names the observable criterion. Research records its examined scope, sources and gaps; external Search/Research can acquire material. The same mechanisms describe Eliot itself, without silently rewriting requirements to make a failing implementation pass.

## 9. Control, supervision and completion

### 9.1 Independent observation with one actual owner

The standalone launcher may start the same binary in supervisor mode. It owns daemon process handles and the selected Job Object covering the daemon/database family. Establish ownership before children escape it; do not kill by process name or a reused PID. A controller/host supervisor may replace this only when it provides that real coverage, not because a configuration label says so.

Observe exit and a service-path health request independently of the worker being observed. A heartbeat thread or file timestamp is not proof the memory path can make progress. Distinguish serving, database-degraded and controlled maintenance. Stop an owned failed family and restart within reasonable configured intensity; intentional idle exit stays stopped. Repeated failures leave a diagnostic rather than a restart storm.

Use standard [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects), not binary-hash attestations for every health poll. Actual Windows launch/nesting/hang behavior remains untested in this documentation stage. The observer has no semantic memory or provider queue and does not require another watcher above it.

### 9.2 Cognitive monitoring and notification

Compare available host events, source changes and reported progress; heartbeat is not progress and a file change is not completion. Missing observation triggers bounded resynchronization and an explicit gap. A small CLI status/inbox/control uses the same stored facts; a later UI is a view.

Deduplicate notifications by the underlying problem and material change, not by retry or newly hashed timestamp. Acknowledgement records delivery, not problem resolution. A failed channel leaves the problem visible locally. Mechanical Doctor repairs may restart an owned worker or reconcile an index; they do not alter meaning, delete material or weaken the goal to make a check pass.

### 9.3 Honest completion

`record_outcome` records facts and claims; external task acceptance stays in the host/controller. Show each declared criterion, relevant revision and observed result. One successful verifier covers only its actual check. Missing verification is unknown, not whole-task success.

No requirement to call a ritual finish sequence, generate a lesson or collect separate proof objects on every ordinary interaction. A source-discovered command is not automatically authorized for execution; use the host's existing permitted tool path.

## 10. Deletion, backup and restore

### 10.1 Defined restrictions without a policy platform

Maintain the minimum current deletion/replay restrictions outside rollback-prone backup images. An append-only file can hold opaque source/delivery IDs or an explicit scope selector and order; do not retain deleted text or a guessable hash of a secret. This is operational retention, not another semantic store or signed audit chain.

The short ingress/retention boundary orders restriction publication against spool replay and content publication. Persist withdrawal before acknowledging it. Physical cleanup may then remove affected primary/derived content, indexes, blobs, caches and controlled backup copies in bounded work; distinguish withdrawal from completed purge.

An old synthesis is not made public merely by removing a private citation. Regenerate from permitted material when appropriate. Already disclosed host/provider bytes remain outside this guarantee. An ID-based restriction covers identified events, not all future paraphrases under unrelated IDs; disable unsafe old replay or use an explicitly new selective import rather than claim semantic erasure recognition.

### 10.2 One conservative backup procedure

Pause primary mutations and new external dispatch; allow short transactions to settle without holding their needed lock. Briefly seal the current spool batch and open a new active batch. Record the sealed cutoff and restriction sequence. Keep primary data quiesced through logical export into a temporary backup directory, together with referenced blobs, sealed input and restriction prefix.

New accepted input belongs to the fresh spool batch outside that backup. Including a committed event also in the sealed spool is harmless when normal restore deduplicates identity. Compulsory full spool drain is unnecessary. Do not wait under the ingress mutex for a worker that needs it.

Only publish the completed-backup marker after required components are present and durable. Checksums identify actual backup bytes, not agent understanding. Interrupted copies are not restore points. Report recovery through the declared cutoff, not through the later wall-clock end of export. This deliberately pays an export-length write pause instead of promising an unverified instantaneous snapshot.

Status and backup cancellation remain available. A conflicting erase either cancels backup or receives explicit busy/pending, never a false applied acknowledgement. The design does not copy open engine files. [Backup reference](https://surrealdb.com/docs/manage/self-hosted/backups-and-recovery).

### 10.3 Restore is not permission to replay past effects

Restore to a fresh directory with ordinary serving and external dispatch disabled. Apply current restrictions, import primary content/blobs, replay permitted staged events by stable identity, and reconcile derived indexes/jobs before switching roots. Check import statements and essential records, not only a process exit code.

Use the current restriction file, not merely its older backup copy. If the whole device/current history was lost, a checksum cannot establish freshness. Keep the recovery isolated until a separately preserved current history or an explicit new selective import defines what may be used. No external attestation service is required to state this limit.

An external job pending in a backup may already have run after its cutoff. Read back its original execution identity before another dispatch. Pure derived work may be recomputed; unknown side effects are not automatically replayed. Keep application semantic revisions in ordinary records; do not rely on engine row history.

### 10.4 Simple schema upgrades

Maintain one current schema version and supported application/server range. Use a completed pre-upgrade backup and a resumable or explicitly failed migration step. An old binary must not ignore a newer schema. No live generation/canary matrix or permanent dual-format facade is required. V1/V2 import is a chosen data conversion, not ongoing backward compatibility.

## 11. Work sequence

Documentation first: complete the concrete reading paths in AUDIT-MAP and reconcile changed contracts. The map is not a mandatory runtime registry. Donor source code is not modified by this work.

After the documentation stage, implement the connected path: demand start → capture/read → context at a real host boundary → actual controller model work → automatic provisional procedure → next attempt/outcome. Include useful control and observation, not a large framework before memory. Then complete remaining project understanding, recursive improvement, additional adapters and recovery scenarios.

Use the owner's development order: product code, minimum relevant checks/Clippy, tests after the product is built. The scenarios below are future acceptance cases, not tests executed now. No inventory-derived issue factory or required import of all donors is needed.

## 12. End-to-end scenarios for the future product

| ID | Situation | Required observable result |
|---|---|---|
| S1 | Unknown note type; model absent; duplicate delivery | One preserved observation and exact read without invented classification |
| S2 | Resume, compaction or non-Git source | Goal, alternatives, commitments and next step reconstructed; missing anchors shown |
| S3 | Familiar resource before an action | Advice reaches a relevant model decision; a pending-tool gate is a separate real capability |
| S4 | Contradiction, false synthesis or poisoning | History/dissent retained; affected influence withdrawn and justification reviewed |
| S5 | Missed file-change event | Affected current views refreshed, unrelated history retained |
| S6 | Prediction before an edit | Named effect compared under matching conditions; correlation remains distinct |
| S7 | Similar error under other conditions | Applicability checked; similarity alone does not block |
| S8 | Method learned from success/failure | Subsequent attempt linked; delivery, action, outcome and benefit distinguished |
| S9 | Harmful transfer | Counterexample retained; affected use narrowed without rewriting old outcomes |
| S10 | Model change, malformed output or foreign target | Invalid transformation rejected; original memory and other routes continue |
| S11 | Incomplete research or absent provider | Scope/gaps explicit; no universal conclusion from empty top-k |
| S12 | Database outage, lost reply or expired worker | Preservation states distinct; stable readback; old claim cannot publish |
| S13 | Service hang | Actual independent observer detects owned failure and performs bounded recovery |
| S14 | Forget, erase and restore | Exposure, influence and purge separate; current restrictions precede serving |
| S15 | Partial result or absent verifier | Criteria/unknowns reported; one local pass does not become whole-task success |
| S16 | Large audit and dissent | Unique coverage, source links and discriminating alternatives preserved |
| S17 | False enforcement | False trigger challenged/narrowed, not a blanket removal of real constraints |
| S18 | Optional failure, pressure, repeated repair | Useful control/read/capture retained; ineffective retries stop visibly |
| S19 | Unreported changes, missed alert or unknown executable | Gaps surfaced; acknowledgement not resolution; no unrequested executable probe |
| S20 | Host/model/tool profile changes | Applicability checked without erasing historical experience |
| S21 | Worker restart after external acceptance | Same execution read back, not another inference caused by a new claim |
| S22 | Replayed/corrected feedback | One current contribution per attempt/criterion |
| S23 | Reordered, short or incompatible vector batch | No silent vector misassignment or zero-vector success |
| S24 | Interrupted backup while capture continues | Incomplete copy rejected; post-cutoff input remains in fresh spool |
| S25 | Old pending external job or stale restrictions | Execution reconciled; uncertain recovery not served as current |
| S26 | Host replays old injected advice | Current applicability clarified; no remote-erasure promise |

All [29 original A15 scenarios](AUDIT.md#12-all-29-original-scenarios) remain. [Cognition §8](COGNITION.md#8-implementation-placement-and-future-walkthroughs) retains its prior cognitive cases and adds recursive-learning cases. These tables do not create separate test platforms.

## 13. Remaining concrete integration choices

| ID | Direction already chosen | What remains unqualified |
|---|---|---|
| O1 | Native Claude hooks + MCP first, truthful advisory timing | Installed events/IDs, continuation and result correlation |
| O2 | Controller execution, independently available text and embeddings | Exact methods/routes, readback retention, cancel and actual constraints |
| O3 | Small event-file spool, current restrictions, quiesced backup | Windows durability/rename details and actual failure handling |
| O4 | Official network SDK first, private Store, native DB operations | Compatible versions/features and concrete schema/query plans; no inherited donor approval gate |
| O5 | Automatic provisional use and conditional transfer; outcome-linked recursive improvement | Appropriate criterion and empirical evidence for claims of broader benefit |
| O6 | One real independent supervisor, reused or small standalone mode | Actual Windows custody/hang/idle and notification coverage |

Unqualified runtime observations are not new architectural blockers. Fix a real interface gap in its owning module; do not add a registry, signature, proof object or approval round for every row.
