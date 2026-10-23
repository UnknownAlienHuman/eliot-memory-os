# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft.14 · 2026-10-23 · concrete design for the greenfield rewrite.**

This document turns [Architecture](ARCHITECTURE.md) into processes, data, operations and integration paths. [Cognition](COGNITION.md) defines the algorithms used by those paths. The [audit conclusion](AUDIT.md) explains why the rejected V1/V2 machinery is not reproduced. The [analysis registry](ANALYSIS-REGISTRY.md) tracks what is checked and what remains open.

No schema, controller method or host adapter described here is claimed implemented until the product code exists. Sections describe the complete target; §2 defines the usable Base and optional capabilities, and §14 defines their delivery order. They are not a requirement to construct every capability before running Base.

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

Use the platform local application-data directory as the stable installation root, for example:

```text
%LOCALAPPDATA%\Eliot\
  config.toml
  data\
    db\
    blobs\
  deletions\
  spool\
  backups\
  logs\
```

`config.toml` contains practical local settings:

- selected data directory (initially `data/`, containing DB and blobs together);
- selected projects/workspaces;
- capture exclusions and retention;
- controller endpoint/routes;
- embedding profile;
- idle timeout;
- optional host adapters;
- optional external research and source tools;
- explicitly allowed cross-project reuse scopes.

It is not a policy database or generated registry. Configuration, spool and the text-free deletion notices in §12 remain installation-owned when restore selects a replacement data directory; an old backup does not overwrite them.

### 1.3 Demand start

The supervisor, not the transient relay, owns a named mutex for the stable installation root throughout startup, operation and shutdown. Selecting a restored data directory does not create a second mutex identity. A relay first connects; if no endpoint answers, it starts a supervisor candidate and waits for the endpoint. Only the candidate that acquires the mutex starts children. Losing candidates exit; their relays can still connect to the winner. An existing owner with an unready daemon is not permission to launch another database. A stable supervisor thread holds the mutex until its children have exited; an abandoned mutex invokes recovery of the selected data directory, not creation of another store.

The supervisor creates a Windows Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, keeps its handle non-inheritable and remains outside that job. It creates each child suspended, assigns it to the job, then resumes it. If assignment fails, terminate that still-suspended child and report the actual launch failure. Start SurrealDB and establish the actual configured database connection before starting/readying the daemon. Do not kill an unrelated process merely because its name or port matches.

The supervisor observes owned process handles and daemon service progress. Restarting a failed daemon does not restart a healthy database. If the supervisor dies, closing its last job handle terminates its owned children; the next demand start reopens the existing store. This does not promise automatic revival while the entire application is inactive. Planned idle shutdown stops new dispatch, settles short mutations, stops daemon and database, waits for their exit, then releases ownership. Requests arriving during startup/shutdown reconnect; capture may stage input with its original identity instead of reporting it committed.

Primary capture and exact/full-text reads become available as soon as Store is ready. They do not wait for embeddings, Dreamer, project orientation or a graph.

These are selected uses of Windows [mutex ownership](https://learn.microsoft.com/en-us/windows/win32/sync/mutex-objects), [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) and [suspended process creation](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags), read on 2026-10-22. The actual installed launch environment, including any parent job restrictions, still needs implementation-time verification.

## 2. Code structure

### 2.1 Source layers and responsibility modules

Start with one Rust package, a library containing the application and a thin executable selecting supervisor/daemon/relay modes. Ordinary modules provide boundaries; one package is a starting choice, not a prohibition on a later useful crate.

| Area | Owns and exposes | Does not own |
|---|---|---|
| `model` | Small shared values: observations, version handles, input/result data and errors actually crossing module boundaries | Vendor SDKs, runtime, a universal contract catalogue |
| `store` | Schema/migrations, fixed queries, atomic writes, exact reads and blobs through its public operations | Interpretation, host protocol, model selection |
| `memory`, `context`, `learning` | Memory operations, pure semantic transformations, context assembly and implemented learning handlers | Raw SDK connections, another scheduler or persistent store |
| `jobs` | Claim/retry/result application for implemented finite work; explicit dispatch to its handlers | Semantic algorithms copied from the handlers |
| `adapters` | Inbound host normalization and outbound controller/source/Research translation, in separate submodules | Task acceptance or a second memory writer |
| `control` | Owner operations, configuration and maintenance using the same application functions | A general policy engine |
| `runtime` | Construction and owned process/task lifetime; `main` selects a mode | Memory algorithms or a global mutable service locator |

The dependency direction is concrete:

```text
model and pure transformations       -> no application or I/O imports
store and outbound adapters         -> shared values; their own external dependencies
application operations              -> shared values, Store API, the outbound clients they use
host / CLI / MCP adapters           -> application operations and shared values
runtime composition                 -> concrete constructors and startup/shutdown
```

Inbound and outbound adapters are not one all-to-all layer. Keep pure packing/reduction code separate from I/O within its owning module; it need not become another crate. Application modules may call another module's public operation where the dependency stays acyclic. A job handler returns its actual result/proposed changes; it does not call back into the runner or implement its own claim loop. Store does not import learning or host code to interpret a row.

Keep SDK connection fields, SQL helpers and module internals private. Expose the few actual entrypoints using normal Rust visibility. `pub(crate)` alone does not enforce an acyclic import graph; review the real imports rather than claiming the compiler proves the architecture. Do not pass the entire application object to every function. Use the concrete Store and small client references; add a trait at a genuinely substitutable I/O boundary, not a repository/service/facade trio for every table. Internal calls share Rust values; serialization belongs at real process/network/storage boundaries.

### 2.2 Base and extensions

**Base** is the first usable configuration, assembled in Slices 1–2: capture from one host, exact/lexical retrieval, addressed current-work facts, explicit notes/corrections with history, source opening, context delivery, local restart/spool and basic data controls. It uses the selected SurrealDB Store, not a temporary substitute to be rewritten later. No controller credentials, embedding model, parser runtime or Research account are needed. Without a synthesis handler, continuation consists of explicitly supplied state plus relevant source events; it is not advertised as automatic understanding.

The following capabilities are separate increments, not a dependency chain:

| Capability | Required input/dependency | Output and existing consumer |
|---|---|---|
| First learning | Base observations, one real controller text/result route, one recipe | Lesson/continuation revision; ordinary `context` and `open` |
| Vector retrieval | Base text revisions, a real batch encoder route | Derived vectors; an additional `context` candidate arm. Does not require Dreamer. |
| Project understanding | Base source access; configured structure tool for structural facts; text route only for generated explanations | Source-linked views; ordinary context. No mandatory full project graph. |
| Document acquisition | Base blobs and jobs, selected external converter | Retained representation and searchable excerpts; source `open`. Does not require Research. |
| Research acquisition | Base result/source storage, selected Research client | External findings/report and excerpts; ordinary memory/context. Does not require a local document converter. |
| Richer cognition | Relevant stored claims/methods/outcomes; text route only for operations that actually infer | Disagreement, anticipation, method revisions and self-diagnosis through the same memory/jobs |
| Another host | Existing application API and that host's real events | The same capture/context paths, not a second memory engine |

The six-table model in §4 is the shared initial storage model, not six fully implemented subsystems required before the first capture. Add fields/indexes with their first real writer and reader. Do not seed fictional recipes or enqueue future job purposes. Common content, provenance and history remain readable when a producer is disabled; rich format-specific presentation may report its own unavailable decoder. Enabling a module uses retained data, not migration to a separate Lite/Full database.

### 2.3 The integration path is ordinary code

For a new capability, implement its operation in the owning module and connect its real caller and consumer. The runtime constructs its client only when selected. Background work adds an explicit branch to the existing job dispatch; foreground enrichment adds a direct call in the owning context/source path. Use the existing capture/publication/result operations. Extend Store migrations and backup/erasure handling only for data actually introduced. This is a small code change set, not a mandatory collection of manifest files or an approval protocol.

For example, vector retrieval adds a controller batch client, an embedding job handler and one candidate query. A content revision schedules that handler only when enabled; it saves matching derived vectors. Context combines those candidates with its unchanged exact/lexical arms. Turning it off stops its new work and queries while the same notes, revisions and source handles remain usable. No second context compiler, vector database, worker supervisor or event bus is created. The actual embedding API is still open work under §9.3/R-015; this example defines its integration, not implemented code.

A function needs no actor. Finite expensive work uses the existing jobs; a long-lived task is used only when it must continuously receive input or retain an actual resource. A subprocess is justified by an external runtime or failure isolation, not by the module name. Replacement is normally a rebuild and graceful restart with retained data. Runtime plugin discovery, dynamic Rust ABI, WASM packaging, hot-reload generations and service-location frameworks are not selected.

### 2.4 Optional means optional in the real path

Runtime configuration chooses enabled operations/routes. Construct an optional client without making every startup probe its remote service; a failure belongs to that capability and must not escape the optional branch as a whole-daemon failure. `attach/status` report supported/configured/unavailable facts from the actual composition and observed operations, not a separate readiness registry. An explicit unavailable operation fails specifically; it does not return successful no-change.

Capture always preserves permitted source input. Only implemented, enabled consumers create optional follow-up jobs; necessary core maintenance remains connected. Disabling a capability stops new dispatch for its purposes. Its pending work is held rather than repeatedly claimed and failed; already dispatched external work keeps its original identity and can retain a useful completion unless explicitly cancelled/erased. Re-enable can continue selected pending work or a finite backfill from retained sources. No full-history interpretation or global reindex is required before reads resume.

A runtime switch prevents work; it does not remove compiled dependencies. Use Cargo optional dependencies/features only where omitting an extension actually reduces the build or package. Keep shared storage readers independent of those features. Do not add a negative `lite` feature that changes record semantics, or a flag per helper. Cargo features combine additively, and transitive dependencies can re-enable defaults: inspect the actual feature graph for a reduced build. Cheap pure logic needs no separate compile flag. External Docling/models are not bundled or downloaded merely because Base starts.

These implementation choices use [Rust visibility](https://doc.rust-lang.org/reference/visibility-and-privacy.html) and [Cargo features](https://doc.rust-lang.org/cargo/reference/features.html), checked 2026-10-23. They require no third-party plugin framework. The old requirements and the deliberately discarded machinery are reconciled in R-033 of the [analysis registry](ANALYSIS-REGISTRY.md).

## 3. Application surface

All host surfaces call the same application functions.

| Operation | Result |
|---|---|
| `attach(workspace, session)` | selected project and stable workspace identity, exact continuation key, binding gaps and actual capabilities |
| `capture(event)` | committed, staged, unknown or rejected |
| `context(decision_frame, budget, retrieval=local)` | packet ID, rendered context, exact included revisions, expansion handles and gaps; explicit `semantic` mode may obtain a query vector (§8.1) |
| `open(handle, read_context)` | exact current/historical item or source segment within the bound project/route |
| `record_outcome(report)` | captured observed result or explicitly sourced report |
| `dream(request)` | finite interpretation/research/improvement job when its handler is available |
| `control(command)` | status/inbox, configure, pause/cancel, correct, erase, backup or restore |

`record_outcome` reuses capture. It does not create an execution-proof subsystem. The adapter supplies the bound project and configured route in `read_context`; opening a source does not require an agent to complete another permissions form. Publish only implemented operations on a host surface; an unavailable handler does not justify a success-shaped stub.

### 3.1 Binding work without a scope platform

Keep stable project/workspace IDs and their configured roots or native resource selectors in the existing configuration. A project can be a repository, ordinary directory, document collection, service or ad hoc work; Git metadata is optional. A workspace ID identifies one configured working instance, not its current path or branch. A confirmed relocation changes that mapping and records the observed move through capture; adding another checkout creates another workspace ID, even when both belong to the same project. Do not derive either ID from a display name, remote URL, commit or copied marker.

`attach` uses the caller's explicit selection or an unambiguous existing configured binding consistent with observed host resources. Native Git worktree metadata can identify linked instances; it does not decide that an unrelated clone belongs to the same Eliot project. An unbound input can be retained under an ad hoc session scope and read there while an existing-project association remains unknown. Do not mix candidate projects or deny all capture until a complete survey is finished. Ask only when choosing an existing binding materially changes the work. A later association is recorded, not a rewrite of old source identities.

Resolve bindings per request/event, not through one mutable global `session.current_project`. A tool reading another root retains that resource's known project/workspace and its link to the originating task; this does not move the whole session. Late events and spool replay use their captured binding, not today's cwd. Composite tasks retain separately addressed inputs and results; no cross-project transaction or automatic union of all project memories is implied. Ordinary configured access still applies.

Continuation addresses use stable project/workspace IDs plus the actual host task identity, or the narrowest actor/session fallback when no task exists. A Git branch, HEAD, dirty status or root path is observed state, not a changing component of that task key. A native conversation fork is different and keeps its own identity. An explicit transfer to another workspace selects the destination continuation and links the prior one; it does not silently rename or merge an interleaved source task. Preserve its goal/commitments while reconsidering only environment-dependent facts.

At attach/resume or a relevant observed resource change, refresh the available location/branch/resource information with ordinary adapter reads. Do not scan neighboring directories, hash the whole repository or acquire a discovery lease before a normal memory operation. Missing state stays unknown. The official [Git worktree documentation](https://git-scm.com/docs/git-worktree), checked 2026-10-23, distinguishes per-worktree HEAD/index and shared repository data and supports relocation; these are adapter inputs, not a new identity service.

## 4. Physical data model

The initial schema uses six primary tables plus filesystem blobs. Context packets and handoff events are ordinary observations and links; they do not require a seventh packet table.

### 4.1 `stream`

Identifies a source/session/agent stream.

Key fields:

- `id`;
- `project`;
- `source_kind`;
- `source_native_id`;
- optional origin workspace ID;
- `last_ingest_seq`.

Unique identity: `(project, source_kind, source_native_id)`.

`last_ingest_seq` records intake in this stream only. It is neither a project-wide clock nor a learning cursor. A source-native cursor belongs to its adapter; interpretation progress belongs to the particular job purpose/target. Parent and child streams keep separate sequence spaces even when they contribute to one continuation. Per-event workspace/resource state belongs on the observation; changing a stream's current metadata cannot relabel its history.

### 4.2 `observation`

Preserves an actual source event, an explicitly sourced report or a directly observed Eliot application event.

Key fields:

- `id`;
- `project`;
- `stream`;
- `event_key`;
- `ingest_seq`;
- `occurred_at` when supplied, retaining precision/timezone uncertainty;
- `received_at`;
- `kind`;
- `body` or `blob_ref`;
- searchable excerpt;
- captured workspace ID and available resource/version or branch state;
- available task/session/branch/call/parent references;
- optional continuation key;
- optional context packet ID;
- optional committed correction result/version handles;
- source locator and revision;
- capture limit if content was partial.

Unique identity: `(project, stream, event_key)`.

An observed tool result, an agent's report about that result, a prepared packet and an observed host handoff are different observations. Immutable source content is separate from optional application metadata. A structured correction observation can hold its committed mutation outcome and exact result handles for replay/readback; it does not need an Operation table. Receipt time does not fill an unknown occurrence or validity time. Replaying an old event preserves these source facts and its original binding.

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
- applicability conditions and exceptions, including structured `applies_to` selectors when known;
- validity interval;
- support assessment/limitations with their reason and source links, separately from retrieval exposure and advisory influence;
- optional commitment data when that kind is implemented (§11.4);
- created/updated times;
- optional embedding vector, effective space and encoded representation/revision (§9.3).

Support is a recorded, scoped assessment, not a universal numeric truth score. Missing assessment stays unknown; it does not prevent capture or a clearly sourced provisional note. Source kind identifies who reported something, not whether the proposition inside the report is verified. `context` reads relevant support limitations and counterevidence alongside the item; exposure changes do not rewrite that assessment. A withdrawn historical item can still be inspected through `open` when retained and accessible, without becoming advice again.

`origin_project` is the stable configured project ID and never changes when the workspace is renamed. Store `reuse_scope` as `{ mode, projects }`: `mode` is `project`, `selected` or `owner`; `projects` is an array of stable project IDs, empty outside selected mode. This describes where a method can be considered, not whether it is true or whether every source can be disclosed. Project-local is the default. Shared methods use the owner's configured reuse choice without a separate approval for every item.

`applies_to` holds only material selectors: optional `workspace_id`, exact `task_key` and known resource/version requirements. Current-work and instance-state producers carry their actual workspace/task association from the input rather than generalizing it to the whole project. A missing state/version cannot be invented from a project match. A reusable method may instead describe portable conditions; unknown conditions stay qualified. This is data used by the existing candidate/packing path, not a scope registry or a classifier required before raw capture. Different working instances can legitimately have contrary current facts without either refuting the other.

`address_key` is an unambiguous application serialization of the full address: project, item kind, address kind and the relevant native components. Continuation uses the stable workspace and actual task or actor/session identity from §3.1; a session-local task ID needs its session component. Git branch/HEAD and mutable root paths are not substituted for that identity. Do not lowercase native IDs or concatenate them with an ambiguous delimiter. A canonical encoded tuple is enough; no digest or address registry is needed.

Project views use a stable view/question key plus the workspace/resource scope they describe; a checkout-specific view is not one shared mutable answer for every checkout. Externally named methods use their stable method key. Processing recipes use an address for the actual project and implemented job purpose (§10.3). Method-outcome contributions use the method revision, actual attempt and criterion identity (§10.5). Both remain ordinary `memory` items. Ordinary anonymous notes have no address. Enforce one current item per complete address, not just faster lookup:

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
- resource continuity/derivation with its observed or inferred qualification;
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
- selected method ID/revision when the purpose uses one;
- current claim and expiry;
- due time/attempt;
- saved controller connection/caller, request method/ID and immutable parameters or their blob reference;
- controller execution and result-artifact references;
- result refs, actually covered input and remaining/unavailable portions;
- error or no-change result.

One target is `(project, purpose, target_key)`. It has at most one active job and one coalesced pending successor. Active includes waiting for or reconciling an already dispatched execution, not merely holding a live worker claim. Completed jobs retain their own input/result history and no longer occupy a slot. Inputs freeze when the pending job becomes active; later events extend the successor only. The multi-stream selection and coverage rules in §10.1 apply to those frozen inputs, not to a global processed flag on observations. Workspace/resource-specific jobs include that scope in `target_key` and freeze it with their inputs. A late completion never resolves its target from the user's newly selected workspace.

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

Locator shapes to implement are concrete; a converter must actually supply the claimed precision:

- code: stable workspace, captured source identity, available revision, path, lines or symbol;
- document/PDF: captured source revision, saved conversion representation and element reference; page/span/region only when available;
- spreadsheet: file, revision, sheet and range;
- image: file/revision and region;
- transcript/media: stream/session, event/turn or time range;
- web/research: captured source or remote revision, retrieval time and representation-specific passage range;
- service/runtime: configured service/environment, actual instance/run identity when available, observation time and retained result.

A generic payload alone does not mean a source type is supported. Keep byte offsets, text-character spans, page coordinates and table-cell positions tagged with their representation and units; they are not interchangeable. A Docling JSON pointer belongs to one saved converted document, not to every conversion of the original file. A newer extraction cannot silently replace the representation named by an old handle (§8.4).

Retain dirty/untracked source bytes or the actually captured range as the cited representation; HEAD identifies a commit, not all working-file contents. A partial tool read is not a full-file snapshot. Existing observation/blob identity is enough to address the retained bytes; no whole-tree checksum is needed before each read. When only metadata was captured, record that limit instead of claiming the old body can be reconstructed from today's path.

A known rename, copy, conversion, crop or export adds an ordinary relation between the captured source representations, retaining the original locators. Use native resource IDs or an observed operation when available. Git's [rename detection](https://git-scm.com/docs/gitdiffcore#_diffcore_rename_for_detecting_renames_and_copies), checked 2026-10-23, is similarity-based; keep that inference distinct from observed object identity. Equal content may share physical storage if supported, but cannot merge logical sources or their evidence counts. Follow exact old handles without resolving through a mutable alias, and do not invent a universal object registry to support these links.

## 5. Store and transaction operations

Store is private application code using the official network Rust SDK and one reusable WebSocket connection to the SurrealDB child. Fixed parameterized query files are preferred to a generic query builder. Export/import use a temporary HTTP connection owned by this same Store, with the SDK `protocol-http` feature and explicit namespace/database selection (§12); the documented Rust WebSocket transport does not support those methods. This is a maintenance transport, not a second application writer.

One writer means one application owner, not that async requests are automatically serialized. Uniqueness belongs in native record keys/indexes; a preceding existence read alone cannot prevent concurrent duplicates. All dependent writes use one explicit transaction. Check statement errors, affected rows and commit, not just a successful SDK response. A zero-row conditional update needs an explicit transaction abort; returning an error-shaped value is not rollback.

Retry a database transaction conflict with the same saved input and identity, without repeating controller calls, parsing or embeddings. A stale semantic revision is different: do not silently replace the expected revision and overwrite another change. For an uncertain commit, read the owning observation/job result first. These choices follow the [transaction](https://surrealdb.com/docs/learn/querying/concepts-and-guides/transactions) and [Rust query](https://surrealdb.com/docs/reference/rust/methods/query) references read on 2026-10-22.

### 5.1 `capture_event`

Inside one short transaction:

1. resolve/create the stream through its unique source identity;
2. read the event key;
3. if identical source input already exists, return its saved result without another observation, sequence increment or queued interpretation;
4. if that identity names different source content, preserve the original and report the mismatch; an explicit correction is a distinct event;
5. advance the stream's ingestion sequence and insert the observation;
6. apply the event's known follow-up rule below for implemented/enabled consumers (§2.4);
7. commit.

Native unique indexes back stream/event identity. Compare source content, not the new receipt timestamp or retry metadata. One stream's sequence orders intake, not the time at which the external event happened. Necessary selected work and source capture commit together, so a lost in-process wakeup is recovered by polling due jobs. With learning disabled, capture still commits and retains material for later selected processing; it does not create an unexecutable job after every event.

Follow-up is selected by the actual event kind and producer, not another model or a generic rule that every write is new experience:

| Input | Necessary next work |
|---|---|
| New host/source event or observed result | Coalesce relevant unprocessed episode or affected-view work when its handler is enabled |
| Explicit structured correction | Apply the addressed edit as described in §5.3; schedule only its affected derived work |
| Model-created lesson or view revision | Refresh its search representation and genuinely affected dependants; do not re-enqueue the same interpretation merely because it wrote a result |
| Packet preparation/handoff, read/status, claim renewal or embedding completion | Optional operational/attribution recording only; no new episode inference or independent support |

Self-diagnosis may select operational events for a concrete observed failure. That does not turn routine accounting into fresh task evidence or start a reflection after every read. Host hooks around Eliot's own `context`, `open` and status tools are operational events too: returning a memory item through MCP does not turn it into independent evidence. Recognize these calls from the configured tool/server mapping, not from words in their output. Explicit new user input or an actual external action remains ordinary capture.

Semantic interpretation, embeddings and source parsing run outside this transaction. When Store is unavailable, publish a complete spool file under the same source identity; acknowledge staged only after its bytes are durably saved using the actual filesystem primitives. A retry must not overwrite another payload under the same key. Replay uses the same application operation and removes the file only after primary readback. For a structured correction, retain the target, expected revision and edit in that same staged command; staged never means applied.

### 5.2 `claim_due_job`

Select due work only for handlers present and enabled in the actual composition. In one short transaction, move a due pending row into the active slot, set its current claim and freeze finite inputs. For text-interpretation work, also resolve the configured purpose-specific method and save its current ID/revision under §10.3; reclamation retains the already selected version. Encoding uses its configured profile, not a Dreamer recipe (§9.3). The unique slot prevents a second active job for that target; a conflict causes another due target to be considered or the short transaction to retry. Concurrent capture either extends the still-pending row or creates its successor after activation. It cannot edit the active input.

The worker then reads its source material and any selected method revision outside the transaction. Reclaiming an expired worker claim keeps the same job, frozen inputs and controller execution reference. It first checks any saved output or ongoing execution; expiry is not permission to buy another model call. Completion requires the current claim and finishes that same row atomically with its result.

Independent projects and targets proceed independently. There is no project-wide head-of-line barrier or separate lock table.

### 5.3 `publish_revision`

All semantic mutation uses one internal function with a caller-owned transaction. It does not open or commit a nested transaction. Both direct corrections and a multi-item job result use the same mutation logic.

Inputs are the create/update target, expected revision for an update, new semantic fields, actual source handles, revision-aware links/grounds, and reason/source identity. The function checks the addressed revision, archives its predecessor, updates the current item and links, and returns the exact resulting version. A replacement also retires the specifically replaced claim within this transaction. Direct creates use a stable ID selected for that command; retries do not create another item. A material premise correction also retains the source-change cause and necessary reconsideration job in this transaction (§8.5); the dependency walk itself runs afterward.

A structured correction is one application command: save its correction observation, apply the edit and record the exact mutation result on that observation in the same transaction. Read an existing result before comparing the target's now-current revision. Retrying a correction that produced revision 4 still returns revision 4 even if another edit has since produced revision 5; it does not reapply the old edit or invent a new conflict.

If the expected revision is already stale and no result exists for this command, retain the correction observation with an unapplied conflict result and leave the target unchanged. A concurrent conflict at commit retries this short transaction and re-evaluates the same expected revision. Natural-language corrections whose target or edit is not yet known remain captured input for ordinary interpretation, not falsely applied commands. No fake job, additional operation ledger or approval service is required.

### 5.4 `apply_job_result`

For a still-live job, persist the actual completed worker/controller result and available execution reference under the existing job or its referenced blob before releasing temporary output. Retain observed/unknown provider usage where applicable; a source converter does not require a fictitious model execution. A target conflict must not discard an already obtained result and silently repeat its conversion or inference. An erasure-cancelled job follows §12.1 instead of retaining deleted input/output again.

For one dependent publication, inside one transaction:

1. return the stored result immediately if this job has already applied it;
2. otherwise verify the current claim and addressed expected revisions;
3. publish semantic changes through `publish_revision`, or update only matching derived fields for an embedding result (§9.3);
4. save exact result handles or explicit no-change and only the input covered by that applied processing (§10.1);
5. finish the job, releasing its active slot, and retain/create any necessary pending successor;
6. commit.

A failed conditional mutation aborts the whole dependent write, including history and job completion. Never implement this as separately committed per-item helpers. Use saved output to retry a storage conflict. If the semantic target has genuinely changed, a short follow-up transaction with the current claim records this job as not applied, releases its slot and coalesces any still-needed reconciliation into the pending successor with the saved output and unconsumed inputs. Do not mark those inputs successfully interpreted or leave an expired active job permanently blocking the successor. Reconciliation uses the current target and saved proposal; a necessary new inference is explicit new work, not automatic repetition of the original request.

An embedding batch groups independent derived updates, not one dependent semantic edit. Its handler may commit bounded groups with per-item applied, stale or error results on the existing job, then finish when every input has a disposition or a retained successor. One edited item does not discard usable vectors for other items. No semantic history revision or reflection is created for vector completion.

An uncertain commit is read back by job ID. An unknown provider outcome is read back by its existing execution reference where supported. Neither is repaired by assigning a new ID and repeating the external request.

### 5.5 `find_context`

Run the independent retrieval arms available in the selected composition:

- direct handles and exact identifiers;
- exact continuation address;
- full-text search;
- compatible vector search when enabled and a matching query vector is available;
- scoped claim-group alternatives;
- relevant typed relations;
- project-local and eligible reusable methods.

Base uses exact/lexical candidates and already recorded state/relations. Optional enrichment supplies candidates to this same assembly path; its absence does not require another context implementation. The caller's local/semantic mode determines whether a query-encoder call is allowed (§8.1), not whether exact knowledge can be read.

The project and workspace come from the bound request, not query prose or a process-wide last selection. Addressed work is read directly:

```surql
SELECT id, revision, content FROM memory WHERE address_key = $address;
```

Local items and reusable methods must be eligible before each retrieval arm's limit. For example, the project/lexical part of a candidate query is:

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

This ordinary task-context excerpt excludes internal processing recipes; explicit method inspection still uses `open`. It specifies project membership and lexical ranking, not the whole query: the production query also applies recorded influence, configured disclosure and known `applies_to.workspace_id`/`task_key` selectors before its candidate limit. Use typed equality against the frame, not substring matches. A state claim scoped to workspace B is not current state of A merely because both share a project; similarly, project-wide view keys cannot substitute for an addressed task. Historical case retrieval can select such evidence with its original scope and time clearly retained. Unknown conditions remain qualified candidates, not fabricated matches or a global read denial.

It never selects a global top-k and then discards other projects. A shared method does not make all raw observations, private project views or its source neighbors shared. Scoped direct expansion and `open` retain that distinction; useful method content can be returned with a specific unavailable-source gap rather than denied wholesale.

Store uses declared scalar types for project/mode/kind and implemented applicability selectors, an array type for selected projects, native indexes on the actual selector fields and `reuse_scope.projects.*` for containment. Keep full-text indexing separate from uniqueness. Use the same eligibility conditions in the native vector query; array containment need not receive the same prefilter optimization as scalar equality. Check the selected server's actual plan before adding another cache or search engine. The [index](https://surrealdb.com/docs/reference/query-language/statements/define/indexes) and [filtered-vector](https://surrealdb.com/docs/learn/data-models/vector-search/similarity-search) references were read on 2026-10-22; these excerpts were not executed.

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

Resolve an exact source locator from its retained representation, not through the current search projection. Reindexing or a changed chunk layout must not make retained, readable source bytes disappear. Source access and actual erasure remain properties of the source, not of a search-generation readiness flag.

## 6. Host capture and delivery

### 6.1 First adapter: Claude Code

Use a command hook calling the same `eliot relay`, not a model-based hook. The [official hook reference](https://code.claude.com/docs/en/hooks), read 2026-10-23, is the source for event fields and delivery behavior below. This is a selected adapter design, not qualification of the owner's installed version. Record that version and available events at setup; an unavailable optional event does not disable supported capture or MCP reads.

| Native event | Eliot operation |
|---|---|
| `SessionStart`, `UserPromptSubmit` | Attach to the actual session/actor and request current orientation. Preserve available `source` and `prompt_id`; resume/compact refresh presentation, not source evidence. |
| `SubagentStart` | Address the child by session plus `agent_id`, retain the observed association and offer initial child context. A repeated start is not a new child merely because the hook fired again. |
| `PostToolUse`, `PostToolUseFailure` | Capture the call's actual input and structured response or error under its `tool_use_id`. Preserve interruption/partial-result fields when supplied. |
| `PostToolBatch`, when supported | Relate rendered results to those same calls, then obtain one packet at the next-model boundary; do not create another execution per batch entry. |
| `Stop`, `SubagentStop`, `StopFailure` | Capture the supplied closing text or error with its actual event kind and make relevant background work due. Do not request another agent turn merely to finish memory work. |
| `PostCompact`, when supported | Record a host-produced view and refresh presentation state, not a new independent observation of the underlying work. Deliver later through a supported context boundary. |

**Identity and correlation.** Encode `source_native_id` from the configured host namespace, `session_id` and `agent_id` when present; otherwise use the main actor within that session. `agent_type` describes a role, not an instance. `prompt_id` correlates a prompt, not every task or execution under it. Keep task IDs only where actually supplied. Session membership does not establish an immediate parent agent or spawning tool call; record such links only from an explicit native association, and use §10.1 if it arrives late. Apply §3.1 to directory/resource changes: refresh the event binding without moving every task in the session. Forked sessions get their own continuation; inherit earlier material only through an observed link, not a similar title or shared path.

For a tool observation, use the scoped call ID plus event phase/representation as its source key. Keep the structured result and the model-visible batch representation distinguishable: they can contain different bytes without being a conflicting replay or two independent outcomes. Reference one execution in §10.5. Preserve actual content in each representation; do not run the tool again to make them agree. For events without a stable occurrence ID, allocate an ingress ID once and retain it through spool retries. This deduplicates Eliot's delivery, not undocumented host re-emission. Do not collapse repeated user text or all starts/stops of one agent into a single event; obtain transcript message identity when available and otherwise retain the uncertainty.

**Final text and late transcripts.** Normalize `last_assistant_message` before passing the event to its handler; preserve absent versus explicitly empty and the event kind. Stop text is an assistant report, not verified execution; on `StopFailure` the same field contains a rendered API error, not a successful final answer. The transcript may lag the hook. A missing/empty current response must not be replaced with an older assistant message labelled current. At `SubagentStop`, keep `agent_transcript_path` separate from the main `transcript_path`; the latter is not the child's log. Where the installed host uses `SubagentHandback` (documented from v2.1.271), capture its `tool_input.message` through the actual tool hook as the submitted report; later closing text is not a substitute. Preserve the call/result association without inferring parent receipt merely from the child's stopping.

Any additional transcript reconciliation reads complete available records in a finite job, with source identity/cursor retained in the existing stream/job. A temporarily unwritten tail remains incomplete. Later matching records can enrich the episode without adding another successful attempt. Parent membership alone does not prove that the parent model received the child's answer.

**Capture before expensive work.** The initial relay synchronously commits or durably stages the permitted event, then exits promptly; it does not await Dreamer, transcript synthesis or a whole-service readiness loop. This avoids relying on a host-owned async process to survive session teardown. Spool/disk failure is visible in Eliot status without blocking the host's tool or claiming capture succeeded. Ordinary memory hooks do not emit permission decisions, `decision: block`, `continue: false` or a blocking exit code. The host remains the task owner.

The adapter tags Eliot-injected blocks and recognizes its own read-tool results (§5.1). Later transcript capture retains new actions and corrections but does not turn those copies into new evidence. Use ordinary observations, links and jobs; no hook coordinator, second transcript store or agent-per-event classifier is needed.

### 6.2 Other hosts

Each adapter maps native events into the same `capture`, `context`, `open` and `control` operations.

Do not create a universal plugin framework before a second real adapter proves the common boundary. Host-specific lifecycle traps remain in that adapter.

### 6.3 Delivery and packet attribution

Build the packet before optional diagnostics. Distinguish preparation, successful local response handoff, host acceptance where observed, and later use. A completed stdout write alone does not prove that the host parsed or retained every field. Automatic hook context uses `retrieval=local`: it does not cold-call an encoder or wait for reindexing (§8.1). Explicit semantic retrieval is a request to the same application path, not hidden work in the hook.

For Claude, return only valid event-specific JSON on stdout, with useful text in `hookSpecificOutput.additionalContext`; diagnostics stay outside that channel. Fit essential claims and exceptions within both the model budget and the documented 10,000-character hook-string cap, leaving details to `open`. Host overflow can become a file preview rather than the full text; the packet record must not claim that omitted material reached the model. The cap and actual installed serialization behavior belong to this adapter, not the general memory schema.

Use `SessionStart`/`UserPromptSubmit` and a supported `PostToolBatch` boundary; use per-tool context only as the chosen fallback, not a duplicate full packet on both paths. Initial child orientation can use `SubagentStart`; changed child advice needs a later supported boundary rather than an assumption that a repeated start reinserts new text. Keep the actual recipient session/actor with the packet. A late background learning result becomes available for the next relevant request; do not inject a precomputed packet into a different current task or wake a stopped agent through `Stop`/`SubagentStop` feedback. If no next boundary occurs, the result remains stored rather than called delivered.

`context` returns `packet_id`. Record the actual handoff under that ID when observable, linking exact rendered revisions. Native call IDs correlate actions/results; the hook schema does not promise to echo Eliot's packet ID. Without further host evidence, offered context is known but adherence remains unknown. Packet-accounting failure cannot erase useful output or change a completed tool's result. Do not demand an additional agent acknowledgement or method-ID form to compensate for missing native correlation.

Repeat suppression is a small cache keyed by recipient, bound project/workspace/task, context incarnation and the rendered item's material qualification/revision. A changed relevant resource condition or binding can require a different qualification even when the method text is unchanged. Resume/compact can re-offer current orientation; old injected context in a resumed transcript is historical delivery, not a new observation or proof that its contents remain current. Re-offer changed corrections without repeatedly sending an unchanged full timeline.

## 7. Current work and context

### 7.1 Decision frame

A decision frame carries available:

- selected project and stable workspace ID;
- exact continuation key;
- native task/session identity and observed Git branch/HEAD separately;
- current user goal and criteria;
- selected resources and their actually observed versions/conditions;
- relevant decision time or explicitly historical question;
- tool/model profile;
- context incarnation;
- token budget.

Unknown fields remain unknown. Goal/criteria retain their user or host source references. An explicit owner revision updates them; a proposed plan, retrieved suggestion or generated continuation does not silently replace them. A factual statement inside a user message remains a sourced assertion rather than an automatically verified external fact. Currentness is checked against supplied facts and recorded changes of relevant resources, not a whole-project fence. An unknown or outdated source condition is shown as such without blocking unrelated context.

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

It does not replace the original events. Reading or delivering a newer tail does not itself advance the saved continuation's coverage. A failed synthesis leaves the last saved continuation plus available unsummarized facts usable. A continuing task can retain its plan across a branch switch while old build/runtime facts are qualified for the state in which they were observed. Do not merge all events in a session merely because a task address is known; use its recorded membership and resource associations.

### 7.3 Packing

`context` constructs whole decision units using ordinary functions over hydrated values; it is not another model or a chain of receipt-producing stages.

1. Keep addressed current work and explicit relevant corrections outside semantic ranking. Resolve a named replacement by its recorded target/scope, not simply the newest timestamp.
2. For candidate items, batch-load the recorded conditions, relevant contrary outcomes and replacement/contradiction links by their IDs. These qualifications need not independently match the query or survive lexical/vector top-k. Follow only relations needed for the selected decision; an unvisited branch remains a specific gap, not a whole-graph readiness requirement.
3. Build a claim with its material exception, a method with its conditions, or an episode with the actual action/result/repair. Structured scope/version facts may determine applicability. Unresolved natural-language conditions stay conditional; lexical overlap and a negation keyword are not an entailment engine.
4. Pack these units within the actual rendered host/model budget. Prefer current corrections and decision-changing limitations before optional background detail. A long high-scoring item cannot evict its own contraindication. Shorten using a faithful stored/extractive unit where possible; otherwise show the qualification plus an expansion handle, or omit that whole unit with the gap stated. Never cut away a negation, version or exception to make a recommendation fit.
5. Deduplicate repeated inclusion by item revision and source occurrence/range. Equal wording alone does not merge distinct sources, claims or obligations. Render saved content, not normalized search tokens, IDs or scores alone.

Candidate examination and final packet size are different budgets. If early candidates are inapplicable, inspect later candidates within the request work limit. Unknown usefulness does not automatically mean exclusion, but not every unknown must be inserted. Empty sections are omitted. Incomplete optional expansion does not suppress unrelated useful units or claim complete coverage. Diagnostic recording and a predicted quality score never gate this return path.

## 8. Retrieval and project understanding

### 8.1 Search

Primary full-text and exact queries operate on `memory` and selected observation fields. Exact cues use the same pure normalization on capture and lookup; preserve canonical path/native-ID spelling and keep any comparison key separate. A cue is a lookup route, not a claim of truth. A note without a cue remains searchable rather than rejected.

**Initial mixed-text analyzer.** Use the native language-neutral tokenization/case-folding path for Base, without a model-language classifier or external NLP service:

```surql
DEFINE ANALYZER eliot_text TOKENIZERS blank, class, camel FILTERS lowercase;
```

Attach it to each implemented full-text field through Store migrations. This is a starting query design, not executed DDL or a claim of optimal Russian/English relevance. It matches token forms; it does not promise stemming, translation or semantic equivalence. Do not apply one Russian or English Snowball stemmer to the entire mixed code/prose corpus, chain language stemmers as a language detector, or strip negations through a generic stop-word list. Language-specific stemming can later add a measured retrieval arm without changing originals or exact identities. Native analyzer behavior and single-field full-text indexes are documented in [DEFINE ANALYZER](https://surrealdb.com/docs/reference/query-language/statements/define/analyzer) and [search indexes](https://surrealdb.com/docs/learn/data-models/full-text-search/search-indexes), checked 2026-10-23.

Paths, qualified symbols, commands, error codes and versions retain typed exact cue keys alongside full-text indexing. Tokenizing a technical identifier must not redefine its identity. Keep the original query and use the same selected analyzer on write and lookup; do not send an entire transcript as an undifferentiated lexical query. Before implementation claims, inspect native `search::analyze` and actual matches for mixed Cyrillic/Latin text, identifier punctuation, case and negative phrases. No custom tokenizer framework is selected.

**One pipeline, two waiting policies.** `retrieval=local` is the default for hooks and Base. It uses available local candidates; the optional vector arm runs only with an already available query vector for the exact query representation and effective space. It never waits for encoder startup, network inference or a background job. An optional bounded cache stores vectors, not packets: its key includes route/disclosure scope, effective space, role and exact encoded query. A cache miss does not borrow a similar query's vector or create a compulsory job after every read.

An explicit `retrieval=semantic` call may obtain one query embedding through §9.3 within that request's configured wait budget. Exact/local reads do not depend on its success. If the encoder is unavailable or times out, return useful local results with the missing semantic arm stated; do not call an empty vector result a completed semantic search. Both modes use the same candidate, applicability, expansion and packing code. New query input is encoded as a query, not looked up among document vectors by text similarity. No Dreamer task is needed to produce it.

**Native candidate fusion.** Use SurrealDB's vector index and `search::rrf` for the lexical/vector candidate union, not a second vector store or an uncalibrated sum of BM25 and cosine scores. Supply lists ordered by their own relevance with deterministic tie-breaking. Obtain their IDs/revisions in a short consistent Store read after any encoder call; fuse ID/rank lists and retain the corresponding version handles rather than letting a generic field merge choose between conflicting revisions. The fusion limit is the candidate-examination budget, not the final packet count. Exact addressed state, explicit corrections and material linked exceptions are fetched independently and cannot disappear merely because they lack a vector score. No mandatory LLM reranker is introduced.

Scope, recorded eligibility and current embedding space belong inside the vector arm before its result limit. Native HNSW evaluates predicates during candidate traversal; indexed prefiltering is a distinct optimization, not promised for every array predicate. Check the actual query plan at implementation time. A full-text match with score zero remains a match: on a small corpus BM25 can give zero to all matches. Keep stable ordering and exact cues instead of filtering `score > 0` or interpreting zero as absence.

These choices follow the [native hybrid search](https://surrealdb.com/docs/learn/data-models/vector-search/hybrid-search), [fusion contract](https://surrealdb.com/docs/reference/query-language/functions/database-functions/search) and [filtered-vector](https://surrealdb.com/docs/learn/data-models/vector-search/similarity-search) documentation checked 2026-10-23. Quality, latency and the selected server's query plans are not yet measured. Applicability and whole-unit packing remain in Cognition §§6.2–6.5; rank is not support or proof.

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
- examined workspace/resource scope and source revisions;
- known gaps.

Source additions, removals, renamed resources and new consumers refresh affected views through ordinary jobs. A failed refresh leaves the prior qualified view usable. Distinguish project-wide intent from an explanation of a particular checkout or document version in the view address and job target. A result computed from an older source remains attributed to it; it cannot certify the newly selected branch. An unrelated edit does not require a whole-project rebuild. A complete-set view also tracks the examined collection boundary so a new member can make it incomplete without changing old cited files.

When the project is Eliot, use the same source/view path for its selected Architecture, implementation sources and observed incidents. `status` supplies current process/job facts; a project view relates those facts to intended behavior without treating either source as proof of the other. Changes refresh affected views normally. No SelfModel service, conformance database or mandatory architecture-read receipt is introduced.

### 8.4 Documents and other sources

Use one narrow external Docling adapter for selected document formats, not a Rust reimplementation, another memory service or a conversion on every read. The chosen path is:

```text
captured original bytes
→ finite conversion job
→ retained DoclingDocument JSON + conversion result
→ searchable source-excerpt views
→ context / exact open of the saved representation
```

**Capture and convert.** Save the original under its source observation before conversion. Pass that retained file/stream to `DocumentConverter.convert`, not a URL that can now serve different bytes. Record converter/core versions, selected backend/options and requested page range on the job. Preserve returned status, errors and available coverage; `PARTIAL_SUCCESS` is returned even with `raises_on_error=True` in the inspected converter. A successful conversion of a requested page range is not coverage of the whole file. Useful partial elements remain readable; unavailable pages are not silently classified as empty.

**Persist one representation.** A conversion-result observation links to the original source observation and to the immutable JSON blob, with its status and processing metadata. The same job publishes searchable excerpts as ordinary `memory` views with `address_kind = source_segment`, addresses including the conversion identity and chunking profile. Their links retain the contributing document-item references. Store only the excerpts needed for retrieval, not an alternative document database. Rechunking a retained representation does not rerun conversion; a new extraction is another representation of the same source, not independent evidence. Old handles continue to resolve their old representation or report its loss.

**Use document structure without inventing precision.** Run the native chunker over `DoclingDocument`, retaining `doc_items`, headings and available provenance beside the chunk text. Use `contextualize` for search/model input when useful, but distinguish its heading/caption prefixes from a literal source quotation. In the inspected `HybridChunker`, plain-text splits reuse the parent chunk metadata; they do not compute a new exact source span for every segment. Merged chunks can reference several elements/pages; table splitting can repeat headers. Do not deduplicate distinct source occurrences by their shared text or count repeated headers as independent support. A fine quote/cell locator is used only when an actual mapping establishes it; otherwise expose the containing element/table and the real excerpt, not a fabricated exact bounding box.

**Open without inference.** The locator carries the source observation, conversion-result identity and item references, plus a representation-specific subrange only when available. Resolve pointers against the retained JSON, then expose the saved text/table structure and available original page/region. Preserve `page_no`, bounding box, coordinate origin and page size together. `prov` can be empty; image cropping requires a page image and the correct coordinate conversion. Missing layout or image data does not prevent reading available text. Keep emitted assets referenced by the saved representation in controlled blob storage, or mark them unavailable before deleting a converter's temporary directory. Opening a citation never buys another OCR/model call or substitutes a newer file.

These choices follow the inspected Docling/Core paths recorded under R-018. They do not establish extraction accuracy or installed compatibility. Spreadsheet cells, media timestamps and other format-native locators still require their own actual adapter mapping; a common document type does not prove those mappings. Retain original material and state the available precision instead of manufacturing them.

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

This optional module adds one controller client, a handler on the existing jobs and the candidate arm in §8.1. The actual controller vector endpoint remains unconfirmed/unimplemented under R-015; the following is the required application contract, not the name of an existing API:

```text
configured profile + role (query or document) + [(input_key, text)]
→ effective space + [(input_key, vector or error)] + observed usage when supplied
```

Memory retains the item/revision/representation association for each key. Controller owns provider-specific request splitting, authentication and model invocation. The caller requests independent embeddings, never one aggregate for all input texts. The adapter translates provider indexes or documented response order back to the original keys; duplicate, missing or unresolvable positions cannot be repaired by padding vectors or assigning the next output to the next record. Validate finite numeric values and expected dimension before storing the vector. Equal vector values for different inputs remain valid separate results.

**Space and input.** The configured space identifies the actual model or documented compatible query/document model pair, dimensions, numeric representation, preprocessing and the role-specific instructions. A route alias or equal dimension alone does not establish compatibility. Map `query`/`document` into the selected model's actual task parameter or prefix; symmetric models may legitimately use the same encoding. Do not silently switch to an incompatible fallback. Text-generation and embedding routes are independent.

Encode an explicitly selected search representation, retaining its identity with the job/vector. Originals and semantic records remain intact. Overlength input is split into addressable source excerpts through the existing representation path, or reported unsupported; a provider's implicit truncation must not be advertised as coverage of the entire source. Applying a vector never converts an excerpt into a new independent observation.

**Real batching and partial completion.** Coalesce changed texts in existing jobs by project, route/space and role. Freeze finite item revisions and group them into requests respecting actual per-input and total token/byte/count limits; a fixed item count is not a universal capacity rule. Use native multi-input calls where they supply independent results. Preserve successful sub-batches as they arrive under the existing job/result path. Retry only remaining failed or unresolved inputs, not an entire completed prefix after one later failure. A sequential fallback is still multiple provider calls, not claimed batching. Background work leaves capacity for foreground queries through controller's existing execution limits; no second rate-limit service is added to Memory.

**Publish only the derived result.** In a short Store update, match the current item/revision and encoded representation, effective space and non-erased job. An old result does not attach to newly edited text. For an applicable result, update only embedding fields and job progress; do not invoke `publish_revision`, rewrite semantic history or trigger interpretation. A content change invalidates its old vector with the primary mutation; the text remains available lexically while replacement is pending. Link/accounting/index maintenance does not call the encoder merely to maintain an unchanged representation. One stale item in a transport batch leaves other matched items usable (§5.4).

**Changing encoders without changing memory.** The first extension uses one configured space in its vector field/index, independently of the Dreamer model. Multiple simultaneous incompatible spaces are not smuggled into that field. On an incompatible space change, pause only vector dispatch/query, settle old vector writers, clear old derived vectors in finite pages and recreate the native index when its dimension/metric changes. Existing job progress makes interruption resumable. Backfill current eligible text through the same handler; the new arm can search the populated portion and report partial coverage without waiting for the whole corpus. Exact/lexical reads and source opening remain available. No dual semantic database, hot-generation platform or model call to regenerate original knowledge is required.

Provider semantics are deliberately adapter-specific. The [Gemini reference](https://ai.google.dev/gemini-api/docs/embeddings) distinguishes independent string-list embeddings in 001 from multi-input aggregation in Embedding 2, and task parameters from task prefixes. [Voyage](https://docs.voyageai.com/docs/embeddings) exposes role, truncation, dimensionality and aggregate request limits. Both were checked 2026-10-23. These examples define what the narrow controller boundary must preserve; they do not select a default provider or establish an installed Eliot route. Source findings and remaining checks are recorded in R-034.

### 9.4 Research

Use the existing Research MCP application boundary, not a new executor or source corpus. At inspected revision `7c034569b908d3b03a8b821b7c537477a24b10f7`, the operations below have real callers, but selected request and citation-reading paths require repairs recorded in R-031/R-032. This is not a qualified deployed integration.

| Need | Existing operation and consumed result |
|---|---|
| Find material without synthesis | `eliotr_query` accepts `FAST_SEARCH` and returns `synthesis_status: NOT_REQUESTED`; hits are not a generated answer. |
| Start requested work | `eliotr_run` returns investigation/workflow identity, not report text or completed execution. |
| Discover retained output | `eliotr_run_status` exposes `answer.availability` and, when available, `artifact_ref` separately from execution state. |
| Read the report | `eliotr_report` returns an artifact envelope with ordered `artifact.sections`; `eliotr_section` returns one exact section's body envelope. |
| Read and expand citations | `eliotr_citations` pairs saved and freshly authorized handles; `eliotr_open` reads evidence, optionally by byte range. |

**Preserve the selected request.** Research's application service parses v5 method/model selection through `parseResearchRunTransportRequest`, but its MCP composition first invokes the v1/v2-only `parseResearchRunRequest`; discovery also advertises the older shape. A v5 owner request is rejected before reaching the capable service. Correct the existing Research schema/decoder/caller chain to share one current application request contract, retaining method, model selection and scope through execution. Do not silently remove those fields, select a default provider, add a Memory-only endpoint or implement a compatibility framework for every discarded request generation. Existing legacy requests remain a separate supported source path, not evidence that the selected newer request works.

Configure the endpoint, explicit Memory-project→Research-project mapping and one authorized profile. Current profile limits remain: managed OAuth excludes MCP cancel/recover; service-token clients use project grants and cannot use `eliotr_source_read` or the inspected owner-only exact model-selection path. Implement a missing selected capability at Research's existing boundary, rather than changing caller identity or putting access machinery in memory helpers. Equal project names are not identity.

**Recover submission, not a new investigation.** Save the endpoint/profile, exact submitted arguments and a stable idempotency key on the existing memory job before sending. If only admission was lost, repeat that request under the same authorized principal. The inspected service binds principal, key and parsed request/selection to the original run, rejects mismatched reuse and dispatches the same Workflow ID. It still performs current scope/configuration checks; replay is not unconditional receipt delivery. Once the workflow ID is known, read status/output instead of repeatedly invoking `run`. A current-access or configuration failure is neither no findings nor justification for a new key. Do not promise permanent exactly-once model execution: native instance identity is retained for a finite period, and the provider-stage recovery path has separate limits. Keep unresolved execution distinguishable from failed acquisition.

**Consume retained content.** Save the returned artifact revision and its section list. Read the needed section revisions in that order, decode `body.text` and retain the actual received bodies plus missing/omitted sections under the job/result. Metadata alone covers no report text. Interrupted reading resumes from those references; it does not regenerate the report. A useful selected section can be retained without claiming the whole report or source collection was read.

Read each used section's citation mapping separately. Retain `original_handle_ref` as the saved citation identity and use the returned `handle_ref` for the authorized evidence read; refreshing a handle adds no independent evidence. Section-level citations do not automatically establish claim-level support. Preserve `semantic_verification: NOT_EXECUTED` when supplied without introducing a mandatory new verifier before useful provisional knowledge can be shown.

The inspected section operation has no range/cursor argument, whereas `eliotr_open` ranges apply to evidence handles, not arbitrary report bodies. The MCP body/envelope bound is 512 KiB; JSON overhead means this is not a safe raw-section allowance. A larger saved section needs bounded reading in the existing Research report reader. Until that path exists, retain the specific read gap; do not invent a range parameter, truncate silently or buy a shorter replacement answer. Byte ranges remain UTF-8 byte ranges, not character indexes.

**Separate citation identity from search readiness.** The current citation reauthorization path calls `pinnedCandidate`, requiring exactly one active, READY/verified search span with the saved parent range before reading the original source. Changed chunk boundaries can therefore make a retained citation unavailable even while its source bytes remain readable. Repair the Research reader to use the saved source representation/range under existing source access, independently of active search projection. Memory's exact reader follows the same separation (§5.6); it must not rebuild an index or rerun research just to open a known source.

A failed citation expansion is not proof that the report is false or that research found nothing. Retain permitted report text with its unresolved-source qualification, respecting actual access/erasure changes. Publish useful findings as ordinary memory revisions linked to the generated report and available primary excerpts. Large corpora stay with Research unless explicitly imported. Existing read-status gaps, deployed credentials and runtime recovery remain in R-016; the old Research receipts, stage graph and activation guards are not adopted as V3 infrastructure. Local recall remains usable.

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

It may create a provisional lesson, update a named lesson, create/update a project view, identify conflict/unknown, or keep/no-change. Once that purpose is configured, the existing handler applies ordinary permitted revisions through §5.4; no new approval queue is required for each lesson. The result retains its provisional/sourced character and cannot rewrite user goals, grant permissions or mark the external task complete. An unresolved semantic alternative may remain alongside existing knowledge rather than force a merge.

Parse failure or provider failure is not no-change. No-change describes an actual completed processing attempt, not a required report from the external agent after every action.

A direct explicit correction uses the atomic observation-and-edit command in §5.3, without a model call. Replay returns the saved version handles or unapplied conflict; it does not repeat the edit.

### 10.3 Method consumer

Separate a processing recipe (how a job interprets an episode or revises a view) from task advice (what an external agent should do in a situation). Both are versioned methods, distinguished by `method_role`; a processing method also names its implemented `processing_purpose`. `job.purpose` selects its matching processing recipe; context retrieval selects relevant task advice. Similar text does not change this role.

Ship real default recipe text for each implemented text-interpretation purpose as application assets. First enablement of that purpose for a project saves its needed default as an ordinary `memory` method using the actual project and a stable purpose address, through the same retry-safe mutation path as other creates. Base setup alone does not seed every future recipe. Record the bundled-file/version origin, not a fictitious successful episode. Concurrent setup resolves the unique address. Do not generate these defaults with Dreamer, seed placeholder purposes that have no worker, or require embeddings before using them.

An optional project/purpose setting may select another existing method ID. Otherwise use the purpose's default address. When claiming a new job, freeze the selected ID and its current revision along with the inputs. The request builder opens that exact body outside the transaction and includes it in the actual controller request. Reclaimed work retains its selection and saved request, not a fresh search for a better method. Encoding uses the provider-specific profile in §9.3, not this recipe selection; deterministic jobs such as applying embeddings or reducing structured outcomes also need no prompt recipe.

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

When a useful result fails, identify the first step supported by available evidence:

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

It enters ordinary context when relevant. Expiry of the warning does not fabricate the outcome or close a separate commitment (§11.4).

### 11.3 Research use

Research findings preserve the question, sources examined, findings, alternatives, coverage/gaps, source handles and method/version used.

A source acquisition failure and completed but uninformative research are different. Repeated no-change on unchanged inputs does not automatically rerun. A clarification asks a concrete question that can change the task or resolve an owner choice; it is not required merely because an internal metadata field is absent.

### 11.4 Commitments and attention without another task manager

An explicitly captured commitment is an ordinary `memory` item. Its kind-specific data contains `state` (open, resolved or cancelled), the known recipient/scope, optional native task reference, optional due time or review condition, and the source of its creation or resolution. It describes what remains owed; it does not own execution of the host task. Base can store explicit commitments without inferring them from arbitrary prose. Later interpretation may propose them with the same source and uncertainty handling as other memory.

`context` reads relevant open commitments by scope/address; `control(inbox)` lists them and actual actionable job/capture failures through existing Store/status reads. Neither depends on vector relevance or another model call. A due time changes ordering/visibility, not resolution. A host result closes a commitment only when its recorded criterion actually matches; otherwise it supplies evidence for the existing interpretation path. An explicit user change uses `publish_revision`. Notification acknowledgement or suppression affects delivery/exposure, not the commitment state.

Optional notification work uses the same finite jobs and existing record references. Do not repeat alerts on every lookup or require an acknowledgement before returning useful memory. With the demand-start service inactive, due items are surfaced on the next start/request; this is not an always-on alarm guarantee. Notifications, semantic extraction of commitments and any external action are independent additions, not prerequisites for the explicit record and its two readers. No AttentionStore, incident workflow engine or global blocking state is introduced.

## 12. Deletion, backup and restore

`control` coordinates these operations through the existing Store, jobs and supervisor. A derived explanation is not disposable merely because a model produced it: restoring the same knowledge requires its saved text and revisions, not another inference.

### 12.1 Deletion

Withdrawal and erasure have different completion results. A committed withdrawal stops guidance; it does not claim that all physical copies are gone. For erasure, record the owner's exact selected source/item scope and command ID as a small durable notice under installation-owned `deletions/` before removing content. It contains stable identifiers and any selected source-occurrence cutoffs, not excerpts or model input. Capture replay, result application and restore consume these notices; unrelated equal text is not a match.

Withdraw the selected material and cancel affected pending/active jobs through ordinary mutations, clearing their claims. Settle their local writers before cleanup; a late controller/converter result must not recreate the erased content through result persistence or spool. Work for unrelated sources continues. Keep only the external execution references needed to report unresolved remote work, not its deleted body. Remote cancellation or external copy deletion is not asserted when the provider cannot perform it.

Page through actual source/derivation references and remove controlled observations, current/history text, conversion JSON/assets, source-excerpt views, packet copies, job input/output blobs, staged files and content-bearing links in the selected scope. Native row/index maintenance removes their indexed entries. Preserve the text-free loss-of-ground qualification before deleting a required link (§8.5). An independently grounded replacement is new content from remaining inputs, not permission to keep the old erased synthesis.

Owned backup sets containing the selected data must be removed or replaced with completed cleaned sets; a deletion notice beside an unchanged dump does not erase its bytes. Never edit a SurrealQL dump with text replacement. Include retained pre-restore data directories in this cleanup. Report incomplete file removals and unavailable controlled destinations; do not label withdrawal as completed erasure. User-exported copies and host/provider logs outside Eliot's control are stated limits. This promises removal from controlled application storage, not forensic sanitization of storage media.

### 12.2 Backup

Use native logical export, not V2's per-record restore protocol or a copy of a live database directory. The backup contains:

- schema and all six tables, including explicit `memory_history`, revision-scoped links, exact method text, saved continuations/outcomes and job execution/result references;
- every retained blob referenced by those rows, including original sources, conversion representations/assets, packet text and collected worker/Research results;
- a finite list of complete staged inputs/results and their referenced bytes;
- non-secret project/adapter settings, schema/server/SDK versions and text-free deletion notices known at the cutoff.

Remote handles alone do not back up remote bytes. Existing unavailable sources remain explicit gaps. Search indexes are rebuildable; exact retained representations and paid model outputs are not replaced by re-extraction. A native export contains current database records, not earlier engine-level versions: Eliot's history survives because `memory_history` contains ordinary records. Do not depend on `.versions()` for it.

The initial backup operation is deliberately serial:

1. Pause new dispatch and primary mutations, drain short transactions and pause blob cleanup. Reads remain available. Do not wait for remote inference to finish; arriving input/results are durably staged under their existing identities.
2. Record the frozen DB scope and finite set of complete spool files. Later arrivals stay outside this backup; no rename of an actively written spool directory is needed.
3. With the same owned server, export the selected database over the Store's temporary HTTP SDK connection into a temporary backup directory. Include records and required schema/analyzers. Keep installation credentials and provider secrets outside the portable copy; provision the target connection through current configuration.
4. Copy the referenced immutable blobs and selected staged files. Consume the export to completion and propagate any stream, statement or file error. A stopped stream or a created filename is not a completed dump.
5. Save a small manifest of actual component paths, sizes/checksums, table counts, versions and spool membership; publish the completed marker only after those bytes are saved. Resume mutations and cleanup on both success and failure. A failed attempt leaves the live data intact and is not offered as a complete restore point.

The [Rust export/import documentation](https://surrealdb.com/docs/reference/rust/methods/export) requires HTTP with `protocol-http`; [backup documentation](https://surrealdb.com/docs/manage/self-hosted/backups-and-recovery) states the limits of record history and copying live datastore files. Both were read on 2026-10-23. These are API choices, not an executed backup or a measured pause duration. No application-wide semantic validation, signed chain or separate backup service is selected.

### 12.3 Restore

The owner's restore command selects one backup and a fresh candidate directory containing DB and blobs together. Keep the installation root, current configuration, spool and newer deletion notices outside that candidate. The same supervisor enters maintenance, stops the live daemon/database child and runs only the candidate database child for import. It does not expose a half-imported target or start another supervision system. On failure, stop the candidate and reopen the unchanged prior data directory.

Import over HTTP into an empty target with the recorded compatible schema/server format. [Native import can commit partially](https://surrealdb.com/docs/manage/instances/import-and-export#partial-imports); failure is not rollback. Retry into a new empty candidate, not over the live database or a half-imported target. Check the actual import result, retained record counts and exact current/history/blob reads. A generated success marker cannot substitute for those reads. Missing components are reported specifically; the owner may select partial recovery of intact content without it being called a full restore.

Before exposing the candidate, apply the union of known current deletion notices and those accompanying the backup, remove their controlled content and cancel affected work. Clear restored worker claims; hold unfinished external jobs for reconciliation instead of treating their old pending/active state as permission to dispatch. A collected result may be applied against current revisions; otherwise read its original external execution reference. Unknown remote execution remains unknown. No new model call is purchased merely to restore memory.

Publish the selected data-directory path through one durable update of the existing installation configuration, under the same installation mutex. Keep the prior directory until explicit retirement, subject to erasure. Startup reads that selection rather than choosing whichever directory looks newest. Current installation credentials/routes are not overwritten by old backup settings. This is a selected cutover design; Windows replacement/durability behavior remains to be verified in implementation.

Replay restored and current spool entries through normal capture/deletion rules with original identities. A staged job result must match its retained job/request; an unmatched result stays unapplied, not a new dispatch. Make primary reads usable after successful import and required native index work; optional embeddings, refreshed maps and new learning do not gate access. Do not imply native import rebuilds indexes asynchronously before it returns.

If current deletion history was lost, the owner may explicitly restore the selected copy with that limitation reported. Intact memory is not quarantined behind an impossible proof. Restoring historical observations or packets does not deliver them again, reinstate old host sessions, or count another successful attempt.

## 13. Control and observability

Direct controls:

- status and scoped inbox;
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

First assemble and test the usable Base; then add independently useful modules. The slices below are work increments, not six compulsory runtime layers or a reason to postpone all testing until the complete cognitive system exists.

### Slice 1 — Store and local lifecycle

Implement supervisor/daemon/SurrealDB ownership, configuration, capture, exact read after restart, spool and direct status/shutdown. Add shared revision/history operations when explicit notes/corrections first use them. This is the first connected persistence path, not a dummy runtime extraction or a claim of finished user memory.

### Slice 2 — Usable Base and its tests

Connect the first Claude adapter, exact continuation lookup and available raw tail, exact/full-text retrieval, explicit notes/corrections, bounded context delivery and source opening. Include explicit commitments and their context/inbox reads (§11.4), not a notification platform. Include pause/stop and backup/restore/erase for the content Base actually stores using §12. Do not wait for advanced self-diagnosis to make retained user data recoverable; later modules extend the same maintenance path for their additional data.

Base is runnable with all model/vector/document/Research capabilities disabled and without their credentials. Its initial useful scenario is a captured result or explicit lesson in session A, a process restart, and the same source-linked knowledge delivered in the relevant session B. It does not claim to infer a new lesson automatically.

After this path is implemented, test it before layering more capabilities onto it: actual Store persistence/replay, revision/correction, scoped retrieval, host delivery and source readback. Include two workspaces of one project, a branch switch with an unchanged task, late input retaining its old binding, and a non-Git scope; these exercise the same Base operations, not a new test platform. Include an absent optional endpoint and a failed capture so neither gets disguised as an empty successful memory. Use the real application operations and the selected database path; no second implementation inside the test or production fake success branch. This is Base acceptance, not a new test platform or release-proof bureaucracy.

### Slice 3 — First learning extension

Add one supported controller text/result pair, finite episode input, one bundled recipe, create/update/keep and the existing result-publication path. Repair the external result gap in §9.1 at its owner. The next actual context consumes the saved lesson. Then add attributable outcomes and method revision consumption as connected increments, checking the changed subsequent request/context rather than just a stored reference.

Test the implemented extension with its real boundary and rerun the relevant Base scenario with learning disabled. A missing text route blocks this extension, not Base, vectors or a deterministic source reader. Do not make its first useful lesson wait for clustering, a whole-project map, Research or recursive improvement.

### Slices 4–5 — Independent capability increments

Use the dependency table in §2.2 rather than treating every earlier slice as a prerequisite. Vector retrieval, project structure/views, document acquisition, Research and additional hosts can be developed separately once their actual inputs exist. Each connects its output to an existing reader and extends maintenance for the content it adds. Keep the specific algorithms and external gaps in §§8–11; do not duplicate those implementations in a module framework.

For each assembled increment, test its actual useful path and disabling/unavailability behavior against Base. Reuse small module-local tests for pure transformations and existing integration checks for changed I/O. A substituted external response exercises local mapping, not proof of the live provider or installed host. Focus on the changed dependency edges rather than generating every hypothetical feature combination.

For vectors, the connected increment is changed text → real independent encoding → matching derived update → semantic query candidates → the existing packet. Check role/index mapping, a failed later sub-batch, an edited item, a space change and the same Base path with the encoder absent. A vector stored in a row without this reader is not delivered semantic retrieval; these checks follow implementation rather than require a new benchmark platform first.

### Slice 6 — Advanced improvement and broader operation

Extend recursive improvement, targeted self-diagnosis, richer disagreement/anticipation and additional source/host integrations when their real consumers exist. Broaden recovery and workload checks for the assembled product; core backup/restore is already part of Base, not withheld until this stage.

Throughout coding, run minimum relevant compilation/Clippy checks. Once each useful increment is assembled, test that increment; do not postpone Base tests until all planned modules exist, and do not start with a speculative test framework. Inspect actual latency, calls, dependencies and retained content before claiming an optimization. Line count is a diagnostic, not a code quota or permission to compress responsibilities into an unreadable monolith.
