# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft.6 · 2026-10-23 · concrete design for the greenfield rewrite.**

This document turns [Architecture](ARCHITECTURE.md) into processes, data, operations and integration paths. [Cognition](COGNITION.md) defines the algorithms used by those paths. The [audit conclusion](AUDIT.md) explains why the rejected V1/V2 machinery is not reproduced. The [analysis registry](ANALYSIS-REGISTRY.md) tracks what is checked and what remains open.

No schema, controller method or host adapter described here is claimed implemented until the product code exists.

## 1. Runtime and first use

### 1.1 Process family

The initial Windows profile uses one executable with modes:

```text
eliot supervisor     owner of the active local process family
eliot daemon         memory service
eliot relay ...      transient host/CLI relay
```

The supervisor owns:

- `eliot daemon`;
- one SurrealDB server child;
- their Windows Job Object;
- restart intensity and planned shutdown.

The daemon does not supervise itself. Hosts and controller do not also own this process family in the initial profile.

### 1.2 Data directory and configuration

Use the platform local application-data directory, for example:

```text
%LOCALAPPDATA%\Eliot\
  config.toml
  db\
  blobs\
  spool\
  backups\
  logs\
```

`config.toml` contains practical local settings:

- data directory;
- selected projects/workspaces;
- capture exclusions and retention;
- controller endpoint/routes;
- embedding profile;
- idle timeout;
- optional host adapters;
- optional external research and source tools;
- explicitly allowed cross-project reuse scopes.

It is not a policy database or generated registry.

### 1.3 Demand start

The supervisor, not the transient relay, owns a named mutex for the selected local data directory throughout startup, operation and shutdown. A relay first connects; if no endpoint answers, it starts a supervisor candidate and waits for the endpoint. Only the candidate that acquires the mutex starts children. Losing candidates exit; their relays can still connect to the winner. An existing owner with an unready daemon is not permission to launch another database. A stable supervisor thread holds the mutex until its children have exited; an abandoned mutex invokes recovery of that same data directory, not creation of another store.

The supervisor creates a Windows Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, keeps its handle non-inheritable and remains outside that job. It creates each child suspended, assigns it to the job, then resumes it. If assignment fails, terminate that still-suspended child and report the actual launch failure. Start SurrealDB and establish the actual configured database connection before starting/readying the daemon. Do not kill an unrelated process merely because its name or port matches.

The supervisor observes owned process handles and daemon service progress. Restarting a failed daemon does not restart a healthy database. If the supervisor dies, closing its last job handle terminates its owned children; the next demand start reopens the existing store. This does not promise automatic revival while the entire application is inactive. Planned idle shutdown stops new dispatch, settles short mutations, stops daemon and database, waits for their exit, then releases ownership. Requests arriving during startup/shutdown reconnect; capture may stage input with its original identity instead of reporting it committed.

Primary capture and exact/full-text reads become available as soon as Store is ready. They do not wait for embeddings, Dreamer, project orientation or a graph.

These are selected uses of Windows [mutex ownership](https://learn.microsoft.com/en-us/windows/win32/sync/mutex-objects), [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) and [suspended process creation](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags), read on 2026-10-22. The actual installed launch environment, including any parent job restrictions, still needs implementation-time verification.

## 2. Code structure

Start with one Rust package and ordinary modules:

| Module | Owns |
|---|---|
| `store` | SurrealDB schema, queries, transactions and readback |
| `memory` | observations, semantic revisions, sources and correction |
| `context` | current-work recovery, retrieval, applicability and rendering |
| `learning` | procedures, improvement lessons and outcome reduction |
| `jobs` | finite background work and claims |
| `adapters` | host, controller, source and research boundaries |
| `control` | configuration, status, maintenance, backup and restore |

Pure transformations remain functions. A module does not automatically get a trait, service, registry or crate.

External boundaries are SurrealDB, host events/MCP, controller text execution/embeddings, optional source tools and optional Eliot Research.

## 3. Application surface

All host surfaces call the same application functions.

| Operation | Result |
|---|---|
| `attach(workspace, session)` | bound project/session, exact continuation key and actual capabilities |
| `capture(event)` | committed, staged, unknown or rejected |
| `context(decision_frame, budget)` | packet ID, rendered context, exact included revisions, expansion handles and gaps |
| `open(handle, read_context)` | exact current/historical item or source segment within the bound project/route |
| `record_outcome(report)` | captured observed result or explicitly sourced report |
| `dream(request)` | finite interpretation/research/improvement job |
| `control(command)` | status, configure, pause/cancel, correct, erase, backup or restore |

`record_outcome` reuses capture. It does not create an execution-proof subsystem. The adapter supplies the bound project and configured route in `read_context`; opening a source does not require an agent to complete another permissions form.

## 4. Physical data model

The initial schema uses six primary tables plus filesystem blobs. Context packets and handoff events are ordinary observations and links; they do not require a seventh packet table.

### 4.1 `stream`

Identifies a source/session/agent stream.

Key fields:

- `id`;
- `project`;
- `source_kind`;
- `source_native_id`;
- `workspace`;
- `last_ingest_seq`.

Unique identity: `(project, source_kind, source_native_id)`.

`last_ingest_seq` records intake in this stream only. It is neither a project-wide clock nor a learning cursor. A source-native cursor belongs to its adapter; interpretation progress belongs to the particular job purpose/target. Parent and child streams keep separate sequence spaces even when they contribute to one continuation.

### 4.2 `observation`

Preserves an actual source event, an explicitly sourced report or a directly observed Eliot application event.

Key fields:

- `id`;
- `project`;
- `stream`;
- `event_key`;
- `ingest_seq`;
- `occurred_at`;
- `received_at`;
- `kind`;
- `body` or `blob_ref`;
- searchable excerpt;
- available task/session/branch/call/parent references;
- optional continuation key;
- optional context packet ID;
- optional committed correction result/version handles;
- source locator and revision;
- capture limit if content was partial.

Unique identity: `(project, stream, event_key)`.

An observed tool result, an agent's report about that result, a prepared packet and an observed host handoff are different observations. Immutable source content is separate from optional application metadata. A structured correction observation can hold its committed mutation outcome and exact result handles for replay/readback; it does not need an Operation table.

### 4.3 `memory`

Holds the current editorial revision of a semantic item.

Key fields:

- `id`;
- `origin_project`;
- `reuse_scope`;
- `revision`;
- `kind`;
- for methods, `method_role` (`advice` or `processing`) and the implemented `processing_purpose` when applicable;
- optional `address_kind` and `address_key` for exact non-semantic lookup;
- `content`;
- `search_text`;
- exact cues and advisory aliases;
- `subject`, `aspect`, `perspective`;
- applicability conditions and exceptions;
- validity interval;
- exposure/influence state;
- created/updated times;
- optional active embedding profile/vector/revision.

`origin_project` is the stable configured project ID and never changes when the workspace is renamed. Store `reuse_scope` as `{ mode, projects }`: `mode` is `project`, `selected` or `owner`; `projects` is an array of stable project IDs, empty outside selected mode. This describes where a method can be considered, not whether it is true or whether every source can be disclosed. Project-local is the default. Shared methods use the owner's configured reuse choice without a separate approval for every item.

`address_key` is an unambiguous application serialization of the full address: project, item kind, address kind and the relevant native components. For continuation, include the host/source namespace, workspace and the task/branch/session identity in its documented uniqueness scope. A session-local task ID needs its session component; a Git branch name alone does not identify an agent task. Do not lowercase native IDs or concatenate them with an ambiguous delimiter. A canonical encoded tuple is enough; no digest or address registry is needed.

Project views use a stable view/question key; externally named methods use their stable method key. Processing recipes use an address for the actual project and implemented job purpose (§10.3). Method-outcome contributions use the method revision, actual attempt and criterion identity (§10.5). Both remain ordinary `memory` items. Ordinary anonymous notes have no address. Enforce one current item per complete address, not just faster lookup:

```surql
DEFINE FIELD address_key ON memory TYPE option<string>;
DEFINE INDEX memory_address ON memory FIELDS address_key UNIQUE;
```

The native unique index permits multiple records with no address. On concurrent first creation, read the winning addressed item and continue with its revision; do not create a second continuation or overwrite the winner. A more specific task identity discovered later selects its own address and may refer to earlier session observations. It does not silently rename a shared session continuation or merge interleaved tasks. No matching address means no saved continuation, not permission to use the latest unrelated one.

### 4.4 `memory_history`

Stores previous semantic revisions.

Unique identity: `(item, revision)`.

A version handle is `(item_id, revision)`. Within a short consistent Store read, return `memory` only if its revision matches; otherwise query this exact history key. No match is missing content, not permission to return the newest revision. An unversioned current-item read uses `memory` only and never resurrects the last historical row after deletion.

Historical reads return their actual editorial status; opening old text is not making it current advice. Keep links/grounds scoped to the requested revision. A current scope or disclosure change still applies to what may be sent now; an old handle is not a permission token.

### 4.5 `link`

Stores typed, revision-aware relations.

Key fields:

- source item/observation and source revision;
- target item/observation and target revision;
- relation kind;
- optional `grounds_group`;
- source locator;
- note/qualification.

Relation kinds include:

- evidence;
- live requirement;
- contradiction;
- replacement;
- episode membership/order;
- outcome of;
- used method;
- included in context packet;
- handed off in context packet;
- navigation/related.

For compound grounds:

- links in one non-null `grounds_group` are required together;
- different groups are alternatives;
- ungrouped evidence is supportive.

For grounding links, the source is the conclusion revision and the target is the premise/source revision. A group ID is local to that conclusion revision, not a global category. An index by target ID/revision and relation kind finds affected conclusions; an index by source ID/revision loads that conclusion's groups. Only grounding relations carry this meaning: navigation, packet inclusion and episode membership cannot acquire it by sharing a group-like label. Reconsideration is defined in §8.5 and [Cognition §3.3](COGNITION.md#33-multiple-grounds), not a general theorem prover.

### 4.6 `job`

Stores finite background work.

Key fields:

- `id`;
- `project`;
- `purpose`;
- `target_key`;
- `state`;
- finite input observation IDs/segments, or exact per-stream ranges with their selection scope;
- input memory IDs/revisions;
- selected method ID/revision;
- current claim and expiry;
- due time/attempt;
- saved controller connection/caller, request method/ID and immutable parameters or their blob reference;
- controller execution and result-artifact references;
- result refs, actually covered input and remaining/unavailable portions;
- error or no-change result.

One target is `(project, purpose, target_key)`. It has at most one active job and one coalesced pending successor. Active includes waiting for or reconciling an already dispatched execution, not merely holding a live worker claim. Completed jobs retain their own input/result history and no longer occupy a slot. Inputs freeze when the pending job becomes active; later events extend the successor only. The multi-stream selection and coverage rules in §10.1 apply to those frozen inputs, not to a global processed flag on observations.

Enforce those slots with one database-derived optional key and a native unique index, not only a query asking whether a job already exists. The selected SurrealQL shape is:

```surql
DEFINE FIELD slot_key ON job VALUE
    IF state IN ['pending', 'active'] {
        [project, purpose, target_key, state]
    } ELSE { NONE };
DEFINE INDEX job_slot ON job FIELDS slot_key... UNIQUE;
```

`slot_key...` indexes the complete tuple rather than each array element; absent keys leave terminal history unrestricted. This is a schema design excerpt, not an applied or executed migration. Native [conditional uniqueness and array indexing](https://surrealdb.com/docs/reference/query-language/statements/define/indexes) support this shape. The row and index are owned by Store, not a second queue coordinator.

### 4.7 Blobs and source locators

Large source bytes live under `blobs/`; database rows keep an opaque reference and digest. Save new blob bytes before committing a row that refers to them. A failed row transaction can leave an unreferenced file for later cleanup; a committed row must not point to a file that was never saved.

Supported locators are concrete:

- code: repository/worktree, revision, path, lines or symbol;
- document/PDF: URI/file, revision, page and element/span;
- spreadsheet: file, revision, sheet and range;
- image: file/revision and region;
- transcript/media: stream/session, event/turn or time range;
- web/research: URL, retrieval time and quoted/span locator.

A generic payload alone does not mean a source type is supported.

## 5. Store and transaction operations

Store is private application code using the official network Rust SDK and one reusable WebSocket connection to the SurrealDB child. Fixed parameterized query files are preferred to a generic query builder.

One writer means one application owner, not that async requests are automatically serialized. Uniqueness belongs in native record keys/indexes; a preceding existence read alone cannot prevent concurrent duplicates. All dependent writes use one explicit transaction. Check statement errors, affected rows and commit, not just a successful SDK response. A zero-row conditional update needs an explicit transaction abort; returning an error-shaped value is not rollback.

Retry a database transaction conflict with the same saved input and identity, without repeating controller calls, parsing or embeddings. A stale semantic revision is different: do not silently replace the expected revision and overwrite another change. For an uncertain commit, read the owning observation/job result first. These choices follow the [transaction](https://surrealdb.com/docs/learn/querying/concepts-and-guides/transactions) and [Rust query](https://surrealdb.com/docs/reference/rust/methods/query) references read on 2026-10-22.

### 5.1 `capture_event`

Inside one short transaction:

1. resolve/create the stream through its unique source identity;
2. read the event key;
3. if identical source input already exists, return its saved result without another observation, sequence increment or queued interpretation;
4. if that identity names different source content, preserve the original and report the mismatch; an explicit correction is a distinct event;
5. advance the stream's ingestion sequence and insert the observation;
6. apply the event's known follow-up rule below;
7. commit.

Native unique indexes back stream/event identity. Compare source content, not the new receipt timestamp or retry metadata. One stream's sequence orders intake, not the time at which the external event happened. New work and source capture commit together, so a lost in-process wakeup is recovered by polling due jobs.

Follow-up is selected by the actual event kind and producer, not another model or a generic rule that every write is new experience:

| Input | Necessary next work |
|---|---|
| New host/source event or observed result | Coalesce the relevant unprocessed episode or affected-view work |
| Explicit structured correction | Apply the addressed edit as described in §5.3; schedule only its affected derived work |
| Model-created lesson or view revision | Refresh its search representation and genuinely affected dependants; do not re-enqueue the same interpretation merely because it wrote a result |
| Packet preparation/handoff, read/status, claim renewal or embedding completion | Optional operational/attribution recording only; no new episode inference or independent support |

Self-diagnosis may select operational events for a concrete observed failure. That does not turn routine accounting into fresh task evidence or start a reflection after every read.

Semantic interpretation, embeddings and source parsing run outside this transaction. When Store is unavailable, publish a complete spool file under the same source identity; acknowledge staged only after its bytes are durably saved using the actual filesystem primitives. A retry must not overwrite another payload under the same key. Replay uses the same application operation and removes the file only after primary readback. For a structured correction, retain the target, expected revision and edit in that same staged command; staged never means applied.

### 5.2 `claim_due_job`

In one short transaction, move a due pending row into the active slot, set its current claim and freeze finite inputs. For model-based work, also resolve the configured purpose-specific method and save its current ID/revision under §10.3; reclamation retains the already selected version. The unique slot prevents a second active job for that target; a conflict causes another due target to be considered or the short transaction to retry. Concurrent capture either extends the still-pending row or creates its successor after activation. It cannot edit the active input.

The worker then reads the named method revision and source material outside the transaction. Reclaiming an expired worker claim keeps the same job, frozen inputs and controller execution reference. It first checks any saved model output or ongoing execution; expiry is not permission to buy another model call. Completion requires the current claim and finishes that same row atomically with its memory result.

Independent projects and targets proceed independently. There is no project-wide head-of-line barrier or separate lock table.

### 5.3 `publish_revision`

All semantic mutation uses one internal function with a caller-owned transaction. It does not open or commit a nested transaction. Both direct corrections and a multi-item job result use the same mutation logic.

Inputs are the create/update target, expected revision for an update, new semantic fields, actual source handles, revision-aware links/grounds, and reason/source identity. The function checks the addressed revision, archives its predecessor, updates the current item and links, and returns the exact resulting version. A replacement also retires the specifically replaced claim within this transaction. Direct creates use a stable ID selected for that command; retries do not create another item. A material premise correction also retains the source-change cause and necessary reconsideration job in this transaction (§8.5); the dependency walk itself runs afterward.

A structured correction is one application command: save its correction observation, apply the edit and record the exact mutation result on that observation in the same transaction. Read an existing result before comparing the target's now-current revision. Retrying a correction that produced revision 4 still returns revision 4 even if another edit has since produced revision 5; it does not reapply the old edit or invent a new conflict.

If the expected revision is already stale and no result exists for this command, retain the correction observation with an unapplied conflict result and leave the target unchanged. A concurrent conflict at commit retries this short transaction and re-evaluates the same expected revision. Natural-language corrections whose target or edit is not yet known remain captured input for ordinary interpretation, not falsely applied commands. No fake job, additional operation ledger or approval service is required.

### 5.4 `apply_job_result`

Persist the actual completed controller output, its execution reference and observed/unknown usage under the existing job (or its referenced blob) before releasing provider-side temporary state. A target conflict must not discard an already obtained answer and silently purchase the same inference again.

Inside one transaction:

1. return the stored result immediately if this job has already applied it;
2. otherwise verify the current claim and addressed expected revisions;
3. publish the dependent changes through `publish_revision` in this same transaction;
4. save exact result handles or explicit no-change and only the input covered by that applied processing (§10.1);
5. finish the job, releasing its active slot, and retain/create any necessary pending successor;
6. commit.

A failed conditional mutation aborts the whole dependent write, including history and job completion. Never implement this as separately committed per-item helpers. Use saved output to retry a storage conflict. If the semantic target has genuinely changed, a short follow-up transaction with the current claim records this job as not applied, releases its slot and coalesces any still-needed reconciliation into the pending successor with the saved output and unconsumed inputs. Do not mark those inputs successfully interpreted or leave an expired active job permanently blocking the successor. Reconciliation uses the current target and saved proposal; a necessary new inference is explicit new work, not automatic repetition of the original request.

An uncertain commit is read back by job ID. An unknown provider outcome is read back by its existing execution reference where supported. Neither is repaired by assigning a new ID and repeating the external request.

### 5.5 `find_context`

Run independent retrieval arms:

- direct handles and exact identifiers;
- exact continuation address;
- full-text search;
- compatible vector search;
- scoped claim-group alternatives;
- relevant typed relations;
- project-local and eligible reusable methods.

The project comes from the bound request, not from query prose. Addressed work is read directly:

```surql
SELECT id, revision, content FROM memory WHERE address_key = $address;
```

Local items and reusable methods must be eligible before each retrieval arm's limit. For example, the scope/lexical part of a candidate query is:

```surql
SELECT id, revision, search::score(0) AS score FROM memory
WHERE (
    origin_project = $project OR
    (kind = 'method' AND (
        reuse_scope.mode = 'owner' OR
        (reuse_scope.mode = 'selected' AND reuse_scope.projects CONTAINS $project)
    ))
) AND (kind != 'method' OR method_role = 'advice')
  AND search_text @0@ $query
ORDER BY score DESC, id ASC LIMIT $candidate_limit;
```

This ordinary task-context excerpt excludes internal processing recipes; explicit method inspection still uses `open`. It specifies scope and lexical ranking, not the whole query: the production query also applies recorded influence and configured disclosure predicates before its candidate limit. It never selects a global top-k and then discards other projects. A shared method does not make all raw observations, private project views or its source neighbors shared. Scoped direct expansion and `open` retain that distinction; useful method content can be returned with a specific unavailable-source gap rather than denied wholesale.

Store uses declared scalar types for project/mode/kind, an array type for selected projects, native indexes on the actual selector fields and `reuse_scope.projects.*` for containment. Keep full-text indexing separate from uniqueness. Use the same eligibility conditions in the native vector query; array containment need not receive the same prefilter optimization as scalar equality. Check the selected server's actual plan before adding another cache or search engine. The [index](https://surrealdb.com/docs/reference/query-language/statements/define/indexes) and [filtered-vector](https://surrealdb.com/docs/learn/data-models/vector-search/similarity-search) references were read on 2026-10-22; these excerpts were not executed.

Union candidate version handles before applicability and final packing. Hydrate their exact versions and revision-specific links, not a later head under the old handle. For selected methods, include relevant recorded outcome qualifications/counterexamples from §10.5 before rendering; a high retrieval score does not erase a known exception. Internal processing recipes are selected by job purpose, not injected as ordinary task advice merely because their text matches. Do not retain a DB transaction across a query-embedding call or host handoff. If current advice needs a newly changed version, fetch it as that version and rebuild the affected unit. Page broad enumeration; a per-page limit is not total corpus capacity.

The result contains a new stable `packet_id`, rendered content, its exact item/method revisions, handles and gaps. Record the versions actually rendered. Packet preparation is useful attribution but cannot suppress useful context on a recording failure; return the packet with a tracking gap instead.

### 5.6 `open_handle`

Open:

- current or historical memory revision;
- observation;
- source segment/blob;
- view and its examined scope;
- job/result status;
- context packet content and included revision handles when recorded.

Use the bound read context for every item and source expansion, including links from shared methods. Return requested immutable source bytes/segments or an explicit availability gap; a live URL or file that now contains different content is not the previously cited revision. A recorded packet opens its saved text and version list, not a fresh rendering with today's methods. Missing content is reported as missing, without a plausible substitute or an implicit latest-version fallback.

## 6. Host capture and delivery

### 6.1 First adapter: Claude Code

Use supported host events rather than inferred execution proofs.

Initial mapping:

| Host boundary | Eliot action |
|---|---|
| Session start / prompt boundary | attach and request orientation/current context |
| Tool success | capture call identity, input reference and actual result |
| Tool failure | capture call identity and actual error |
| Batch/turn boundary when supported | request context informed by recent results |
| Resume/compaction boundary | refresh current work and changed advice |
| Explicit user correction | save and apply a structured correction command together; otherwise capture for interpretation |

`attach` returns the exact continuation key chosen from the narrowest available native task/branch/session identity. Subsequent host events and context requests carry that key when available.

The adapter records what the host supplies. It does not invent a task ID, verifier, successful step or project. Subagent events remain in their native child/parent streams and are not flattened into a fictitious single sequence.

The adapter tags Eliot-injected context. When later conversation is captured, exact injected blocks are excluded as new source evidence while genuinely new user/agent actions and results remain. Previously delivered advice is not counted as independent confirmation merely because it reappears in the transcript.

Capture returns without waiting for Dreamer. A wakeup only makes interpretation due.

### 6.2 Other hosts

Each adapter maps native events into the same `capture`, `context`, `open` and `control` operations.

Do not create a universal plugin framework before a second real adapter proves the common boundary. Host-specific lifecycle traps remain in that adapter.

### 6.3 Delivery and packet attribution

Build the packet before optional diagnostics.

Distinguish:

- packet prepared;
- handed to the host;
- observed by the host if such feedback exists;
- applied by the agent, usually unknown unless later evidence supports it.

`context` returns `packet_id`. The adapter records an observed handoff event under that ID when it actually hands the packet to the host. The packet record links to every included method/item revision. Later action/outcome observations carry the packet ID only when the host can correlate them; otherwise adherence remains unknown.

Packet accounting failure does not erase the rendered packet or transform a known primary action into failure. Do not mark handed off before the handoff. Logging failure cannot erase a known primary result.

Repeat suppression is a small cache keyed by context incarnation and material revision. New corrections or newly available orientation may be offered again.

## 7. Current work and context

### 7.1 Decision frame

A decision frame carries available:

- project/workspace;
- exact continuation key;
- task/session/branch IDs;
- current user goal and criteria;
- selected resources;
- tool/model profile;
- context incarnation;
- token budget.

Unknown fields remain unknown.

### 7.2 Continuation before similarity

Context construction:

1. directly open the continuation by exact key;
2. merge relevant observations outside its recorded per-stream/segment coverage (§10.1), including late-linked child material;
3. retrieve exact constraints and corrections;
4. retrieve applicable methods and episodes;
5. resolve current claim groups and dissent;
6. add optional project view and relation expansion;
7. pack the decision.

A cancelled plan or old continuation does not regain authority by similarity.

A continuation is an ordinary versioned `memory` item with `address_kind = current_work` and the exact continuation key. It contains:

- active goal;
- current plan;
- completed work;
- rejected/abandoned approaches;
- open commitments;
- last relevant results;
- next useful step;
- source handles, represented streams/segments and coverage gaps.

It does not replace the original events. Reading or delivering a newer tail does not itself advance the saved continuation's coverage. A failed synthesis leaves the last saved continuation plus available unsummarized facts usable.

### 7.3 Packing

Pack semantic units, not isolated rows:

- claim with material exception;
- failure with repair/result;
- method with conditions;
- dissent with its distinguishing check.

Candidate examination and final packet size are different budgets. If early candidates are inapplicable, inspect later candidates within the request work limit.

Render useful content, not only record IDs and scores. Details remain available through `open`.

## 8. Retrieval and project understanding

### 8.1 Search

Primary full-text and exact queries operate on `memory` and selected observation fields. Vector search is an additional arm.

Embedding identity includes encoder, preprocessing and content revision. A failed or pending vector leaves exact/full-text retrieval available.

Background embedding work is batched and limited so foreground query capacity remains.

### 8.2 Relations and episodes

Expand only relations that supply missing information: order, consumer, cause, repair, outcome or exception.

An intermediate node need not repeat query words. Use relation type, direction, scope and work budget; do not scan all links or encode every visited node again.

A short lesson may expand to its source episode: relevant preceding action, result, repair and check. Episode order comes from stream/call/result links, not timestamp proximity across unrelated work.

### 8.3 Project structure

Use configured existing tools rather than an embedded parser platform.

Initial code-structure adapter: `codebase-memory-mcp` when configured. Request compact architecture/package/entry-point structure and open exact sources as needed.

Fallbacks such as manifests, ripgrep and direct source reads provide partial structure with explicit limits. They do not claim a complete call graph.

Project views are ordinary versioned memory items:

- purpose and boundaries;
- subsystem/area explanations;
- recurring question answers;
- examined scope and source revisions;
- known gaps.

Source additions, removals, renamed resources and new consumers refresh affected views through ordinary jobs. A failed refresh leaves the prior qualified view usable.

### 8.4 Documents and other sources

Use external converters when useful; do not embed another memory runtime.

Docling is the initial document/PDF converter candidate. The adapter preserves the original file/revision and maps converted elements back to pages/spans.

Spreadsheets, images and transcripts use their concrete locators. Unsupported detail remains accessible as original bytes/handle and is not silently treated as indexed.

### 8.5 Reconsider affected grounds

A source correction, refutation, relevant live-requirement change or erasure records its actual scope and a follow-up job with the primary mutation. Ordinary new editions, temporary source unavailability and reduced exposure are not automatically refutations. The worker uses the reverse grounding index to page through affected conclusion revisions, then loads each conclusion's own complete groups. It does not walk navigation links as evidence or rebuild every project view.

Use the group rules in Cognition §3.3 to preserve an unaffected alternative basis, identify a broken basis or retain uncertainty. This reduces known dependency facts; it does not decide arbitrary semantic truth. An unresolved relation may require one targeted interpretation with the changed premise and affected conclusion. No model call is needed merely to identify the incoming links or a declared broken group. The actual consumer is `context`: return the known qualification with the selected claim/method before a replacement explanation is ready, rather than silently serving it as unchanged established advice.

A change job retains its cause, traversal position and remaining IDs in the existing `job`. Continue in finite pages, deduplicating a conclusion revision within that cause. A material change to a conclusion can affect its dependants; a timestamp, repeated visit or unchanged assessment cannot start an endless cascade. Cyclic citations alone supply no independent ground. Newer source changes remain pending rather than being swallowed by completion of the earlier cause. No-change cannot mean that an unvisited branch was checked.

Normal reads use recorded premises, corrections and affected-state information for selected items, not fresh remote validation or a whole-corpus proof. If a relevant dependency expansion is unfinished, identify that qualification; do not call the item fully resolved, deny all memory, or wait for unrelated work. Historical evidence is not invalid merely because a live requirement has changed. A known refutation is not hidden behind a generic stale-view label.

When erasing a premise, retain the permitted fact that an affected required group lost a member before removing that member's link. Do not evaluate the shortened or empty group as the original complete derivation. Keep no deleted content in that marker. An alternative ground can preserve the conclusion's support, but cannot authorize retaining prohibited bytes in its old synthesis; required cleanup or a new derivation from allowed inputs remains separate. Exact deletion and restore implementation is still covered by §12 and R-020, not declared complete here.

## 9. Dreamer and controller

### 9.1 Text execution

Dreamer is a job purpose, not a separate service. The adapter uses controller's existing command and artifact operations. Source review at `70b99db3d8732d10a69d03d1dbe83afdd39a7229` confirms the replay and byte-read mechanisms below, but also a public-result projection gap. The complete Memory OS integration is not implemented; R-014 and R-027 in the [registry](ANALYSIS-REGISTRY.md) separate the useful existing paths from the required repair.

**Submit and recover the same request.** Prepare finite input and open the exact method revision. Before each state-changing controller request, save its configured connection, caller identity, `client_request_id`, method and submitted parameters on the existing job or referenced blob. Do not regenerate the request from newer memory or a new timestamp when reconnecting.

The inspected Store deduplicates by `(caller_id, client_request_id)` and compares method and canonical parameters. An exact replay returns the saved admission receipt before reapplying the command; changed parameters under that ID are rejected. Therefore, if the acceptance reply was lost, resend that saved request to the same controller as the same authorized caller. If no admission occurred, it can be admitted; if it did, the original receipt is returned. This is controller request recovery, not permission to replay a native prompt. Save the returned Operation ID and read current progress with `operation.get`: the admission receipt deliberately remains unchanged after completion. A new caller or another controller is not the same deduplication scope.

**Obtain the actual result.** The adapter follows this path once the projection gap below is repaired:

| Step | Existing operation and consumed result |
|---|---|
| Submit finite interpretation | Supported `task.dispatch` request; save its exact Operation/Attempt/session association, not just the newest session output |
| Obtain a result page | `agent.result` for that source Operation and byte range; save the result-read Operation ID and obtain its persisted artifact handle and next range through public readback |
| Assemble when needed | `artifact.assemble` over the collected page handles; save its admission Operation ID, then read its completion and output handle rather than treating the admission receipt as completed bytes |
| Read the body | `artifact.read` for that handle, with `offset_bytes`/`length_bytes`; the inspected reader allows 1–65536 bytes per request, so continue until the retained body is collected |
| Apply knowledge | Preserve the body and its limits on the memory job, parse it, then use §5.4 without another inference merely to recover delivery |

Use the configured controller client authorized for the relevant task and artifact. The native adapter's Module credential is not that client: the inspected public byte reader rejects Module-role calls and separately resolves artifact byte access. A reference identifies a result; it does not grant access. Reuse that existing boundary instead of exposing controller files or constructing a permission system in Memory OS.

**Required controller repair — publish the usable handle.** In the inspected code, page registration and assembly finish store `details.artifact_ref` and completion/range information. Public `operation.get` passes results through `project_result_receipt`, which copies a method-specific list of top-level scalar fields but not those nested details. Its assembly list includes `artifact_id`, which the successful assembly producer does not write there. The proposed consumer therefore cannot obtain the stored output handle from this response even though the internal result says applied.

Repair the existing method-specific public projection to expose the actual artifact reference, completion condition and, for a page, its offset/length/total/EOF/next range. Preserve error codes and the existing object-read checks. These are required response data, not a new endpoint, proof package or broad export of private JSON. Do not compensate in Memory OS by deriving internal artifact filenames, opening controller's database, scraping logs or requesting the answer again. Other result-discovery paths have not been ruled out; this finding concerns the specified `operation.get` consumer.

**Continuation and retained output.** The inspected normalized `agent.result` admission requires a source `task.dispatch`. The prepared-Claude-specific helper also requires that dispatch, not an arbitrary `agent.send`. Do not advertise a reusable conversation route merely because its send method exists. Extend the actual controller source-Operation/result mapping when continuation is selected, retaining the real input/Attempt association; never relabel a continuation as the first dispatch or create another attempt solely to retrieve its old answer. A steer may affect an existing turn rather than produce its own terminal response.

Input admission, native completion, complete retained bytes and a usable parsed proposal remain distinct. EOF on one page does not establish earlier coverage; a complete assembly of a captured prefix can still be truncated. Preserve those flags and unknown usage. Empty, failed or malformed output is not successful no-change. A separately usable partial proposal may be retained as partial without marking the entire input processed.

Reconnecting for a saved receipt does not recover native bytes lost before durable capture. Existing registered artifacts are read through controller; uncollected source-body retention, adapter restart and successor recovery remain open route-specific work, not a promise supplied by A2 documentation. Retain collected output before releasing its source. A failure of this route leaves raw capture and other working memory functions available, without a new model executor or result journal in Memory OS.

### 9.2 Request content

A Dreamer request includes:

- concrete question/purpose;
- finite source observations/segments;
- current relevant methods/items;
- exact selected method ID/revision when improving behavior;
- output contract: create, update, keep/no-change, or report uncertainty;
- source handles and disclosure route.

The model may propose memory revisions and links. Application code checks parseability, addressed membership, current revisions and job claim. It does not certify truth. Route fallback never silently expands disclosure or budget beyond configuration.

### 9.3 Embeddings

Controller needs a batch vector operation:

```text
encoder profile + [(item_id, text_revision, text)]
→ per-item vector or per-item error
```

This is controller model infrastructure, not an agent task. Until implemented, V3 remains useful through exact/full-text retrieval.

Applying a vector updates derived fields for the matching content/profile. It does not create a semantic revision or trigger another learning episode.

### 9.4 Research

The required Research adapter contract is:

```text
question + scope + source constraints + budget
→ status + report + source handles + examined coverage + gaps
```

Eliot Research owns acquisition and large corpora. Eliot stores the compact findings/alternatives needed later and links to the underlying sources.

This contract is a required implementation target, not a claim of an existing endpoint.

## 10. Learning

### 10.1 Episode input

Host events are grouped using actual session/task/call/result relationships. Chunking a large log for search does not define a task boundary. A shared episode may use several streams without flattening their native order or waiting for every child agent to finish.

A job freezes the relevant stream membership and observation IDs/segments. Per-stream ranges may compact that identity only when the recorded selection scope and omissions make the set exact. There is no single `last_processed_seq` across streams: A through 120 says nothing about B through 8. A newly received B:9 is still new even when its occurrence time precedes A:120. When a known parent/task relationship is learned late, capture of that relationship also schedules the already retained child observations not covered by this target; considering only future arrivals would miss them.

Keep input selection, request material and committed processing coverage distinct on the existing job. The request builder records which observation bodies/segments were actually supplied and which older material was reread only for context. An opaque handle that was never expanded does not establish that its body was processed. A token limit, unread blob or missing tool result cannot be hidden by advancing coverage to the highest selected sequence. Use actual source IDs/segments, not a model's assertion that it read everything; this is input accounting, not proof of understanding.

On apply, save only that processing's covered set, method revision and explicit gaps with the result. Complete no-change covers the actual input for that purpose, not omitted material or all future uses of those sources. Deferred IDs/segments are coalesced into the pending successor without duplicating newer events. Deliberately excluded or currently unavailable material has an explicit disposition, not a false success and not an unchanged automatic retry forever. Source return, new membership, new evidence or an explicit request can reopen the affected work.

Continuation carries the coverage used to build it, per stream and segment where necessary. `context` reads relevant material outside that coverage; a sparse set must not become a contiguous high-water mark across a hole. Reading the same observation for a project view does not consume it for episode learning. No global processed flag, second cursor database or event broker is needed.

Use indexed `(project, stream, ingest_seq)` reads with a frozen upper bound and continuation by the last actual sequence, not an ever-growing offset or occurrence timestamp. Select useful portions across relevant streams so a busy stream does not indefinitely displace a quieter child's result. Keep available call/result and repair/check links; if a counterpart has not arrived, retain that gap and proceed with independent useful material. The saved observation is not deleted to make a model's input format convenient. New arrivals extend only the pending successor, never the running request.

### 10.2 Interpret, correct or keep

A normal Dreamer job receives:

- the relevant episode slice;
- explicit user feedback/corrections;
- a small set of related current lessons;
- the selected method revision used to interpret or improve.

It may create a provisional lesson, update a named lesson, create/update a project view, identify conflict/unknown, or keep/no-change.

Parse failure or provider failure is not no-change.

A direct explicit correction uses the atomic observation-and-edit command in §5.3, without a model call. Replay returns the saved version handles or unapplied conflict; it does not repeat the edit.

### 10.3 Method consumer

Separate a processing recipe (how a job interprets an episode or revises a view) from task advice (what an external agent should do in a situation). Both are versioned methods, distinguished by `method_role`; a processing method also names its implemented `processing_purpose`. `job.purpose` selects its matching processing recipe; context retrieval selects relevant task advice. Similar text does not change this role.

Ship real default recipe text for each implemented model-based purpose as application assets. First project setup saves the needed defaults as ordinary `memory` methods using the actual project and a stable purpose address, through the same retry-safe mutation path as other creates. Record their bundled-file/version origin, not a fictitious successful episode. Concurrent setup resolves the unique address. Do not generate these defaults with Dreamer, seed placeholder purposes that have no worker, or require embeddings before using them.

An optional project/purpose setting may select another existing method ID. Otherwise use the purpose's default address. When claiming a new job, freeze the selected ID and its current revision along with the inputs. The request builder opens that exact body outside the transaction and includes it in the actual controller request. Reclaimed work retains its selection and saved request, not a fresh search for a better method. Deterministic jobs such as applying embeddings or reducing structured outcomes do not need a prompt recipe.

Restart and software upgrade do not overwrite learned/user-edited methods with bundled defaults. Missing or withdrawn explicitly selected content is reported for that job; it is not silently replaced by a semantically similar note. First-use initialization is not a repair loop that recreates deliberately removed methods. Other capture/read paths remain available.

Textual improvement updates the addressed method through `publish_revision`; subsequent jobs read the new revision automatically, while running work keeps its original input. Proposals for another recipe remain separate until selected; a freshly generated method does not replace the current one merely because it exists. No promotion ladder or new approval step is required for an ordinary permitted revision. Code algorithms and configuration change through their actual owners, not because a prompt describes a different implementation.

A method without a real consumer is stored knowledge, not implemented self-improvement.

### 10.4 Applicability and transfer

Applicability is three-valued:

- applicable;
- inapplicable;
- unknown/conditional.

Similarity finds candidates; it does not prove conditions. Negation, version and observed execution results must not be reduced to word overlap.

Cross-project retrieval considers current-project items and reusable methods whose `reuse_scope` includes the current project.

Origin and source restrictions remain visible. Transfer may be provisional; broad effectiveness requires later comparable outcomes.

### 10.5 Outcome feedback

Keep source events in `observation`. A tool result and an agent's report about it may both be retained, but they are not two independent attempts. `packet_id` identifies offered context, not an execution or proof of adherence.

`learning` reduces attributable feedback into an ordinary versioned `memory` item of kind `outcome`, with `address_kind = method_outcome`. Its complete address includes project, exact method ID/revision, the actual attempt/execution identity in its native namespace, and the criterion including the checked target/profile. A whole Task or session is not the attempt identity when it contains several executions; use their actual operation/run association or retain the uncertainty. Keep multiple checks of one attempt as criterion-specific results; do not count them as several independent attempts. Without a reliable attempt or method association, preserve the useful report/episode with that gap instead of inventing an ID or crediting every method in its packet.

The item retains source observation handles, offered/handoff facts where known, actual action, adherence or unknown, criterion coverage, result, competing failures/cost and comparative benefit or unknown. Use `publish_revision` for a changed interpretation or explicit correction. Reprocessing the same sources with the same result is no-change, not another contribution or semantic revision. An explicit correction replaces that contribution with history; two incompatible reports without an ordering basis retain disagreement, not last-writer success. Aggregates read current contributions for comparable conditions rather than incrementing permanent success counters on every delivery.

Structured check results use ordinary reduction code. Ambiguous explanations may use the existing episode/method interpretation job. A missing diagnostic is success only if the relevant check covered the target; an unrelated failure is not automatically a failed method.

There are two actual consumers. `context` loads relevant limitations and observed counterexamples with a selected method, even before its prose has been revised; it labels reports and unknown attribution accordingly. `learning` supplies materially new feedback, the addressed method and original observations to a coalesced revision job when interpretation can change the next decision. That job may keep the method, narrow a condition, add an exception or produce a useful alternative. A successful repair, cheaper successful route or explicit correction can trigger this path too; not every successful tool invocation needs reflection. No-change and operational accounting do not retrigger it by themselves.

Example of the selected design, not an executed result: a lesson is shown for API v2, then a real failed attempt reveals that it applies only to v1. The outcome and its conditions become visible with the lesson; a revision narrows that lesson, and the next v2 context no longer presents it as applicable. Merely logging the failure or increasing a score would not complete this loop.

### 10.6 Recursive improvement

Use the same jobs, methods and outcomes for task-local Propose–Probe–Compose and cross-task lessons about how to improve.

Baseline/no-change remains eligible. Repeatable local calculations and copies are preferred probes. Do not repeat irreversible external actions merely to compare candidates.

### 10.7 Self-diagnosis

When a useful result fails, identify the first failed step:

- event not captured;
- lesson not produced;
- lesson not retrieved;
- context not delivered;
- advice not used;
- advice inapplicable;
- advice used and harmful.

Correct that step. A failed repair blocks unsupported repetition of that repair, not all diagnosis under the same configuration.

## 11. Disagreement, anticipation and research use

### 11.1 Disagreement

Represent rival explanations as ordinary claims with grounds and counterevidence.

Select the cheapest useful discriminating observation. Additional agents are optional controller tools. A vote or number of agents is not evidence.

Unresolved alternatives remain available; unrelated work continues.

### 11.2 Anticipation

A conditional anticipation is a method or claim describing trigger situation, expected risk/opportunity, material conditions, useful check/action and expiry/reconsideration condition.

It enters ordinary context when relevant. Expiry of the warning does not fabricate an outcome.

### 11.3 Research use

Research findings preserve the question, sources examined, findings, alternatives, coverage/gaps, source handles and method/version used.

A source acquisition failure and completed but uninformative research are different. Repeated no-change on unchanged inputs does not automatically rerun.

## 12. Deletion, backup and restore

### 12.1 Deletion

Publish withdrawal before acknowledging it. Remove controlled current/history rows, links, vectors, blobs, staged input and controlled backup copies as required.

Keep the minimum replay/deletion information outside rollback-prone copies. Do not retain deleted text in that record. Loss of a required premise is recorded on the affected conclusion/group before removing its link (§8.5); removing provenance is not a new derivation or a way to preserve erased content.

### 12.2 Backup

1. pause primary mutations and new external dispatch;
2. let short transactions finish;
3. seal the current spool batch and open a new one;
4. export primary DB state and referenced blobs into a temporary directory;
5. include the sealed input cutoff and known deletion information;
6. verify required components;
7. publish the completed-backup marker;
8. resume.

New input remains in the new spool batch. An interrupted copy is not a restore point.

### 12.3 Restore

Restore into a fresh directory. Apply known current deletions, import primary data/blobs and make primary reads available before embeddings and views finish rebuilding.

If current deletion history was lost, the owner may explicitly restore the selected copy with the limitation reported. Do not quarantine all intact data behind an impossible proof.

Old external jobs do not restart automatically. Reconcile execution references before any repeated provider/tool effect.

## 13. Control and observability

Direct controls:

- status;
- inspect/open;
- pause/resume jobs;
- cancel owned work;
- configure routes/projects/retention;
- correct/withdraw/erase;
- backup/restore;
- graceful shutdown.

Status is derived from actual process, Store, jobs and recent results. Heartbeat is not progress; acknowledgement is not resolution; prepared context is not handoff.

Optional notification failure does not block status or control.

## 14. Implementation sequence

Build vertical slices in this order.

### Slice 1 — Store and local lifecycle

- supervisor, daemon and SurrealDB child;
- configuration/data directories;
- capture event;
- exact open/read after restart;
- spool when Store is unavailable;
- direct status/shutdown.

### Slice 2 — Host capture and context

- first Claude adapter;
- actual tool result/error capture;
- exact continuation key and current-work lookup;
- exact/full-text context;
- stable packet ID and handoff observation;
- `open` expansion;
- advice delivered at a real model boundary.

### Slice 3 — Dreamer and lessons

- actual controller text execution and same-request admission recovery;
- public result handle through authorized artifact bytes, including the controller projection repair in §9.1;
- finite multi-stream episode input and actual processing coverage, with bundled initial recipe and purpose-based selection;
- shared `publish_revision` for job output and direct correction;
- create/update/keep;
- method revision consumed by the next job;
- source-linked current outcome contribution, correction and a changed subsequent context/method; packet linkage alone is not demonstrated use.

### Slice 4 — Understanding and transfer

- codebase-memory-mcp adapter;
- affected project views and premise-change reconsideration through existing links/jobs;
- origin/reuse scope;
- cross-project method retrieval;
- disagreement and anticipation.

### Slice 5 — Vectors, documents and research

- controller batch embeddings;
- Docling/source locators;
- Research request/result adapter;
- hybrid retrieval and richer sources.

### Slice 6 — Recovery and advanced improvement

- backup/restore/erase;
- recursive improvement;
- targeted self-diagnosis;
- additional host/source adapters.

For each slice, implement the real production path first. Run minimum relevant build/Clippy checks. Add broader tests after connected behavior exists. Do not create success-shaped stubs, fixtures in the production branch or unused framework code to satisfy a planned test.
