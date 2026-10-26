# Eliot Memory OS V3

**Layered Base and additive extensions · 2026-10-25 · normative design, not implemented code.**

V1 and V2 are donors. V3 is a greenfield implementation.

## Reading order

1. [Architecture](ARCHITECTURE.md) — purpose, ownership, Base, extensions and non-goals.
2. [Implementation](IMPLEMENTATION.md) — runtime, modules, data, Store/RPC/durability contracts and implementation order.
3. [Cognition](COGNITION.md) — current-work reconstruction, retrieval, learning, consolidation and self-improvement algorithms.
4. [One-shot inference contract](INFERENCE-CONTRACT.md) — sole Memory↔controller boundary for connections, profiles, disclosure, controlled payloads, readback and all cleanup dispositions.
5. [Active analysis registry](ANALYSIS-REGISTRY.md) — what was checked, exact gaps and the next work queue.
6. [Audit conclusion](AUDIT.md) — evidence, root causes, rejected mechanisms and source limits.
7. [Requirements/source map](AUDIT-MAP.md) — stable dispositions for original requirements, audits and donors.

Architecture, Implementation and Cognition describe one product at increasing depth. `INFERENCE-CONTRACT.md` is the narrow cross-repository contract for one selected external boundary; it is not another architecture or workflow layer. The complete target is not a prerequisite for running Base. None of these documents is implemented product code.

`ANALYSIS-REGISTRY.md` is the only active analysis ledger. `AUDIT-MAP.md` is the stable source/decision matrix; new work updates the registry rather than creating another chronological report.

## Selected construction

One local Rust package/codebase, one demand-start supervisor/daemon family, one external SurrealDB child and one private Store. Domain/pure logic, application operations, external adapters and host surfaces keep explicit dependency direction without requiring a process, actor, contract crate or pass-through service per concept.

Base captures real host/source events, preserves explicit knowledge/corrections/commitments, supplies exact/lexical context and reopens exact sources after restart. Its maintenance covers the data it actually retains. Base starts without controller, model, encoder, converter or Research credentials.

Learning, vectors, project understanding, documents, Research and additional hosts are independent vertical extensions. They reuse the same records, finite jobs, revision publication, context assembly and maintenance path. A missing extension does not disable Base; disabling a producer does not erase retained readable knowledge. There is no second Lite database or Full memory engine.

## Store and local durability baseline

V3 does not assume that naming an SDK or database makes persistence correct. The Store baseline is explicit:

- exact SurrealDB server path/version/size/digest and storage engine are installation-owned inputs;
- the first qualification target is SurrealDB 3.3.4 with external RocksDB and explicit `sync=every`; no silent fallback to SurrealKV, another version or another URL spelling;
- the supervisor launches one numeric-IPv4 loopback child with a sanitized environment, metrics/identification/slowlog/telemetry/Postgres/import disabled and no inherited arbitrary `SURREAL_*` settings;
- the loopback port is selected per start, not trusted from a prior file: a temporary reservation narrows the race, and Windows TCP-table listener plus established-peer ownership must match the retained child process before any credential is sent;
- the live HTTP surface is RPC only and the only allowed RPC method is `query`;
- database/root authentication and namespace/database selection occur in a Basic-authenticated WebSocket upgrade on the already verified raw TCP stream; RPC `signin`, `use`, `version` and `ping` are not exposed;
- exact binary digest plus process/listener/peer ownership establish service identity; WebSocket control Ping/Pong establishes transport liveness;
- `--allow-origin` is not WebSocket authorization: SurrealDB's CORS middleware adds response headers but the RPC upgrade does not reject Origin, so Origin is defense-in-depth metadata only;
- unauthenticated WebSocket upgrade remains possible upstream, but guest arbitrary query is denied; anonymous connection-exhaustion behavior must pass Slice 0 or trigger a separate pinned-WSS/proxy hardening decision;
- root credentials exist in a child environment only for the short first bootstrap: after possible root persistence the child is stopped and the same store restarts without root environment material before root RPC provisioning;
- a failed/unknown bootstrap retries with the same retained root credential after root-free reconciliation, never a newly generated password;
- Memory uses a small bounded JSON WebSocket client, not the current Rust SDK or V2 adapter;
- JSON carries only explicit application DTOs: no generic Surreal `Value`, `SELECT *` persistence format or implicit `NONE`/`NULL`, record-ID, UUID, datetime, duration, decimal or non-finite-float round-trip;
- only fixed application queries with bound JSON-safe variables, explicit projections and exact decoders are exposed;
- the database is `STRICT`, the six application tables are `SCHEMAFULL`, and schema generation/definitions are verified before mutation;
- database-scoped Editor owns ordinary runtime access; database-scoped Owner owns migrations, user rotation and typed restore; root is not a normal daemon/migration credential;
- database users are provisioned from current Credential Manager secrets through locally derived Argon2 `PASSHASH`, never plaintext `PASSWORD` in SurrealQL/argv/logs;
- composite unique indexes own occurrence/idempotency/cardinality where possible;
- snapshot-isolation conflicts retry the whole immutable transaction only after exact classification/readback;
- transport, shutdown or grouped-WAL-sync failure after possible application is `OUTCOME_UNKNOWN`, not rollback;
- shutdown/backup quiesce returns private `stage_required` before Store ownership, so relays publish the exact command to spool; public `rejected` is never overloaded as temporary deferral;
- V3 owns backup/restore as canonical typed pages over six tables plus exact blobs, deletion notices, pending and retained failed spool and a sanitized configuration snapshot; Surreal logical export/import and live-engine copying are not the application contract.

The official Rust SDK may be reconsidered later, but the current 3.3.4 dependency requires Rust 1.95 while this repository declares MSRV 1.94, and its published license metadata does not fit the current `cargo-deny` allowlist without an explicit preflight. A dependency is not admitted because its API looks convenient. V3 also does not copy SurrealDB's vendor-specific CBOR tag protocol into another client.

Store admission requires exact binary identity, retained process handle, observed listener owner, observed established peer owner, upstream `/ready`, Editor Basic handshake with exact authentication/selection headers, the query-only route/method/subject/function denial matrix, schema/definition checks and one bounded typed write/read/delete through the production client. Port, `/health`, `/status`, `/ready`, TCP connect, WebSocket 101 or clean child exit alone proves none of that.

Normal shutdown first closes mutation admission, returns `stage_required` for new direct capture, drains finite admitted work, closes daemon Store sockets and requests the qualified graceful SurrealDB path. Job Object termination is deadline/crash containment only. SurrealDB bounds maintenance drain and can continue after logging cleanup failures, so restart always repeats full admission and application readback.

The first Windows durability profile is a local fixed NTFS/ReFS volume. Immutable blob/spool/deletion/backup publication uses:

```text
create-new same-directory temporary file
→ write + file FlushFileBuffers
→ no-replace same-volume MoveFileExW with WRITE_THROUGH
→ parent-directory FlushFileBuffers
→ reopen and verify exact bytes
```

`MOVEFILE_REPLACE_EXISTING` is forbidden for immutable publication. Rename success followed by failed parent sync/readback is post-commit unknown, not `staged`; reconciliation must verify the final file and complete directory sync. The same rule applies when replay deletes/moves a pending entry or when backup/cutover files are published.

Backup pages use a versioned canonical application JSON Lines encoding with fixed DTO field order, stable application-identity ordering, no unordered maps/sets and digests over exact bytes. The manifest owns completion. Unsupported backup/schema generations are refused explicitly rather than fed into a speculative generic migration system.

These mechanisms remain unimplemented until Slice 0 proves the exact Windows binary/profile, `sync=every`, dynamic port and listener/peer ownership, Basic-authenticated query-only transport, Origin non-authority, anonymous-connection bounds, short/reconciled root bootstrap, credential split, typed wire DTOs, transaction/unknown behavior, `stage_required`, graceful/forced shutdown, durable publication and canonical application backup/typed restore round-trip.

## First Base host and durable capture

The first integrated host profile is one Claude Code hook relay because it supplies real lifecycle, prompt, tool-result and final-response boundaries. Claude-specific JSON is an adapter input, not the Memory domain model. Other hosts arrive later through the same `capture`, `context` and `open` operations.

The initial event profile is deliberately small:

| Event | Base purpose |
|---|---|
| `SessionStart` | Reopen the exact continuation and return real bounded context on `startup`, `resume`, `clear`, `compact` or `fork` |
| `UserPromptSubmit` | Capture the submitted user input and return decision-time context before the model request |
| `PostToolUse` | Preserve a successful tool call, its native `tool_use_id`, input and returned result |
| `PostToolUseFailure` | Preserve a started tool call that failed, including its error and interruption facts |
| `Stop` | Preserve the main agent's final `last_assistant_message` without waiting for transcript freshness |
| `SubagentStop` | Preserve the final subagent response and native agent identity; handback tool results remain tool events |
| `PostCompact` | Preserve the generated compact summary as a derived representation, never as replacement source truth |
| `SessionEnd` | Preserve the session lifecycle boundary and reason |

`PreToolUse`, permission and stop enforcement are not Base memory requirements. Negative memory is advisory by default. A later host guard is explicit and opt-in; V3 does not carry forward a general lease, finish or compaction gate merely because the old plugin had one.

### One capture command, one occurrence identity

The relay builds one complete bounded `CaptureCommand` before any daemon call. It contains a relay-generated command ID, native host/session/task/resource coordinates, event kind, native event key when available, occurrence time, exact accepted body or blob, body digest, disclosure, locator and explicit capture limits.

Occurrence identity is separate from content equality:

- native IDs such as `session_id`, `tool_use_id`, prompt/message/agent IDs are retained when supplied;
- the relay command ID is the fallback occurrence key and the idempotency key for direct delivery and spool replay;
- the content digest verifies bytes but never merges two real occurrences merely because their payloads match;
- an identical replay of the same command returns the original Store result; another occurrence with identical bytes remains another observation.

Capture exclusions run before durable publication. Accepted source bytes remain exact within the declared bound. Extracted index fields are separate projections. A generic key-name sanitizer must not silently remove URLs, endpoints, paths, final messages or other source locators; any omitted or host-truncated material is recorded as an explicit capture limitation.

### Direct delivery and spool are the same operation

There is no successful `forwarded` state without Store readback.

```text
build exact CaptureCommand once
→ call daemon `capture`
→ committed only after Store identity/digest readback

stage_required / lost / unavailable / uncertain direct result
→ atomically publish the same command to `spool/pending`
→ staged only after durable file publication
→ daemon replays the same `capture` operation
→ delete pending file only after Store readback
```

`stage_required` is internal direct-delivery control, not a fifth public capture result. It is returned before Store/blob ownership when mutation admission is closed. The daemon is the sole replayer. Corrupt or permanently rejected entries move to `spool/failed` with a bounded non-content reason; they do not loop forever. Successful replay removes the pending body instead of maintaining a second `committed` content archive.

The public capture outcomes mean exactly:

- `committed` — the Store owns the observation and exact readback matched;
- `staged` — the exact command is durably present in the pending spool;
- `unknown` — neither Store commit nor durable spool publication can be established;
- `rejected` — deterministic validation, exclusion or bound failure before ownership transfer; temporary quiesce is not rejection.

### Context is content, not a service-status phrase

`SessionStart` and `UserPromptSubmit` return the actual rendered context packet through the host's supported context channel. A message such as “event spooled” is status, not context.

A packet is retained through ordinary V3 data rather than a `PacketStore`: one Eliot application observation/blob records packet ID, rendered digest, budget, gaps and exact included revisions; ordinary links record inclusion and an observed host handoff. Keep these states distinct:

```text
prepared
→ emitted through the host contract
→ associated with a later action when observable
→ actually used or influential: usually unknown unless separately observed
```

If context construction or the hook fails, Base capture and explicit retrieval remain available. The host receives a specific context gap rather than fabricated empty success, and no local output file is counted as delivery.

The first implementation must qualify the installed Claude Code version and actual payloads. The current public hook reference is a design input, not proof that a user's installed build emits every current field.

## Exact open and bounded reads

`open` is not a broad query with an empty selector. It requires one nonempty exact handle or source locator and an optional bounded range. Search and context generation may suggest handles; only `open` resolves one of them.

Exact handles identify what the caller asked to read:

- current semantic handle — resolve the current revision or return explicit absent/withdrawn/erased state;
- version handle `(item_id, revision)` — return that exact historical revision or explicit missing/damaged state, never silently substitute current;
- observation/source handle — return the retained source body/blob representation and locator actually captured;
- transformed representation handle — return that representation and its relation to the original, never silently reconvert or replace it with a newer source.

A content digest verifies bytes. It is not a public logical handle unless the object is explicitly content-addressed.

### Exact result envelope

Every exact read reports actual disposition rather than an empty list with implied success:

```text
requested handle and revision/range
resolved identity and representation
returned byte/item range and digest
current/history state
material conditions, limitations and capture gaps
relation descriptors needed to interpret the item
expansion handles
next cursor when more retained bytes or relation descriptors exist
missing | forbidden | erased | damaged | unsupported representation
```

`requested`, `returned`, `missing` and `forbidden` are populated from the real read. `truncated=true` requires a valid continuation for the omitted readable portion or an explicit non-pageable gap. A fixed relation cap without continuation is incomplete coverage, not a complete exact read.

Opening one claim or method does not require loading every source body, but it must not hide the existence of its material grounds, contradictions, replacements, exceptions or outcome links merely because the caller did not already know both relation endpoints. Return bounded relation descriptors and expansion handles from the revision actually opened. Expanding a neighbor body is a subsequent exact read.

Current and historical relations are revision-aware. A link supporting revision 2 does not silently describe revision 3. Relation discovery and body expansion are separate, but neither may depend on semantic top-k.

### Bounded byte and item pagination

Ranges and cursors bind to the exact object/revision/representation and read options. A cursor cannot be replayed against another source or a changed current revision. The result states whether limits apply to rows, bytes, decoded elements or rendered text; one does not masquerade as another.

Large text/blob reading is metadata/excerpt first, then exact byte or representation ranges. UTF-8 boundaries are handled explicitly. Long JSON, one very long line, PDFs, images and spreadsheets retain format-specific coordinates where available.

An empty exact-handle list returns a validation error or empty exact result by the owning operation; it never means “read the project broadly.” Broad navigation uses a separate bounded query with its own scope, denominator and cursor.

## Why V2 stalled and what V3 forbids

The preserved goals were not the main problem. Continuity, correction, provenance, negative memory, project understanding, Dreamer, privacy, recovery and operator control remain useful. The failure came from turning each principle into its own owner, registry, receipt, lifecycle and proof ceremony, then rewarding production of those artifacts instead of integration.

Repository delivery postmortems add a second causal layer: cheap deterministic blockers were checked after expensive preparation; overlapping branches and PRs lacked one queue owner; new sibling work started without backpressure; and documentation/conformance output displaced connected product paths. V3 therefore uses these constraints:

- one live analysis ledger, not another task catalogue, gate, mission database or report database;
- one semantic owner and one current branch/PR disposition for overlapping work;
- cheap admission and configuration failures before expensive build, download or agent dispatch;
- completion only for a real caller → owning operation → durable result or typed unknown → actual consumer → restart/readback path;
- deletion or replacement of superseded authority instead of append-only clarification;
- product code and a connected vertical slice before generalized workflow, plugin, policy or proof infrastructure;
- merged product behavior and closed blockers as progress, not prose, LOC, commits, agents, issues or PRs.

These rules constrain implementation and documentation. A new process artifact is justified only when a concrete product field cannot be represented by the existing owner and the new mechanism replaces or materially simplifies something already present.

## Preserved goals, minimal mechanisms

The old Architecture often stated the right intent: preserve sources, separate observation from interpretation, keep authority explicit, degrade locally, challenge false rules and prefer the simplest reversible mechanism. The later Implementation made many replaceable defaults globally mandatory. V3 keeps the intent and removes machinery that is not needed by a connected product path.

| Preserved goal | V3 minimum | Not carried forward by default |
|---|---|---|
| Resume interrupted work | Stable project/workspace/task address, retained observations and direct reconstruction | Universal Understanding State, route-continuation registry or mandatory checkpoint protocol |
| Preserve source and provenance | Observation + immutable blob/range + exact source/revision handles | Separate EvidenceAtom, Truth Registry, evidence promotion service or receipt for every read |
| Correct memory without rewriting history | One versioned memory item, revision history, grounds and current applicability | Global truth score, promotion ladder or dedicated correction subsystem |
| Prevent repeated mistakes | Scoped negative memory or method revision returned by normal retrieval | FailureFingerprint platform, universal quarantine state or mandatory experiment campaign |
| Deliver useful context | Exact/current-work lookup, lexical candidates, optional vector arm and bounded packet over actual revisions | Separate Context Compiler service, packet database or acknowledgement ceremony |
| Learn from episodes | Finite Memory job, exact recipe revision, narrow one-shot inference, typed result/no-result state and later consumer | Permanent Dreamer process, controller Task/Attempt for one completion or model-owned publication |
| Add optional capabilities safely | Internal module and vertical increment; external process only for a real runtime/failure boundary | Crate/process per noun, mandatory `module.toml`, promotion contour or hot-swap framework for ordinary helpers |
| Protect privacy and secrets | Disclosure propagated with content; authoritative check at actual send owner; finite controlled-copy cleanup | General Governor policy engine, route classifier, approval packet or capability-evidence platform |
| Recover after failure | One Store, source spool, application-owned typed backup/restore, supervisor and idempotent operation/readback | Second recovery database, Operational Recovery State ontology or global Product Identity graph |
| Keep authority explicit | Narrow application operations and authenticated external boundaries | One universal Governor for ordinary in-process calls or receipt-backed authority for every transition |
| Improve methods from outcomes | Observed result linked to exact method revision and a new revision when evidence changes it | Global intelligence score, StepOutcomeLedger or compulsory model judge |
| Coordinate development | One issue, one branch/PR owner, one integrator and terminal disposition for overlap | Work-unit database, branch manager, generated inventory denominator or agent scheduler |
| Verify product behavior | Lowest connected product edge that distinguishes the property; broader proof only at corresponding boundary | Shape/module proof counted as product completion or full release identity for local change |

A mechanism enters V3 only after its real caller, owner, retained result and consumer are named. Until then the need remains a requirement or test case, not a new type, service, manifest, registry or process.

## Model execution without a second task manager

Dreamer is the cognitive role of a finite Eliot learning job, not a permanent process or controller Task lifecycle.

Successful result path:

```text
retained episode + exact recipe revision + disclosure
→ saved exact Memory request
→ direct authenticated controller IPC
→ controller inference_input + one inference Operation
→ frozen InferenceConnection / InferenceProfile behavior
→ controller inference_result
→ Memory range read + length/digest verification + durable copy
→ purpose-specific decoder
→ ordinary memory revision or valid no-change
→ changed later context
→ inference.release(memory_copy_verified)
```

Terminal no-result path:

```text
rejection / failed attempt without result / queued cancellation
→ explicit operational failure, not cognitive no-change
→ inference.release(terminal_without_result)
→ retained input removed or exact cleanup gap
```

Physical erasure of unresolved work uses `abandon_for_erasure`: controller fences future dispatch/settlement/publication before removing exact controlled copies. This cannot prove that provider execution, storage or billing did not occur.

`eliot-swarm-controller` remains the initial owner of model/provider credentials and external execution. It needs narrow `inference.text`, `inference.embed` and `inference.release` operations that reuse request deduplication and durable result readback **without** creating a controller Task, Requirement, Attempt, workspace, review or acceptance record. Memory owns its job, source coverage, recipe, disclosure reduction, result copy, decoding and publication.

Controller configuration separates transport/secret ownership from behavior selection. A static `InferenceConnection` owns transport, private credential reference, non-secret digest and declared `actual_destination = local | external`. A static `InferenceProfile` selects one versioned adapter, one connection, one requested model, automatic-use permission, finite limits and supported response formats. The resolved profile inherits actual destination from its connection. There is no implicit fallback.

Memory reduces contributing input to `local_only` or `external_allowed`; controller authoritatively checks the resolved destination. Protected input is not silently omitted to make a remote destination pass. Missing usage, cost or account identity remains unknown rather than zero or inferred.

Controller stages exact input before provider I/O and exact visible result when one exists. Input and result cleanup are tracked independently. Aggregate `released` is valid only when every created controller content copy is removed or verified absent. The exact request/result/no-result/abandon lifecycle is defined in [INFERENCE-CONTRACT](INFERENCE-CONTRACT.md).

Real software-agent work with tools and continuation can still use controller Tasks/Attempts. One memory extraction request cannot justify copying that task system into Memory OS.

## Product path

```text
real host/source event
→ durable observation
→ direct current-work and memory retrieval
→ optional finite interpretation
→ versioned lesson/view
→ context at a later decision
→ observed result
→ correction or method improvement
```

Base implements capture, explicit updates and reuse. The first learning extension closes automatic interpretation and later use. Every capability needs a real input, operation, retained result or typed unknown, and consumer. A stored type, receipt, fixture or generated card is not product behavior.

## Development order

[Implementation §14](IMPLEMENTATION.md#14-implementation-sequence) defines connected slices:

0. Exact SurrealDB/Windows preflight: binary/profile/`sync=every`, sanitized environment, dynamic port plus listener/peer owner, Origin non-authority and anonymous-connection bounds, peer-verified Basic query-only transport, reconciled short root bootstrap, Owner/Editor `PASSHASH`, typed JSON DTOs, transaction/WAL unknowns, `stage_required`, graceful/forced shutdown, immutable publication and canonical application backup/typed restore including pending+failed spool and config comparison.
1. Store/lifecycle and exact persistence.
2. Useful Base with one host, retrieval/context/source open and maintenance.
3. Controller one-shot inference owner: connection/profile admission, direct IPC, controlled input/optional result, exact readback and per-copy `inference.release` without Task/Attempt.
4. First Memory learning path: disclosure, exact recipe, retained request/result or explicit no-result, decoder/publication, later context and correct cleanup disposition.
5. Independent vector, project-view, document, Research and host increments.
6. Advanced curation and diagnosis after base paths work.

Write production code first. Run minimum relevant build/Clippy after coherent code increments. Do not build a speculative test platform or distort production code to satisfy placeholder tests. Full automated suite is built and run after connected product implementation.

For every slice, resolve cheap blockers first, keep one integrator and give overlapping work terminal disposition before opening sibling branch. Leaf compilation, generated documentation or stored receipt does not close a slice.

## Evidence limits

The audit conclusion covers available corpus and records explicit exclusions. Full release ZIP contents and `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` were not available as readable source material. Donor findings apply only to exact paths/revisions recorded in registry; no donor is qualified wholesale.

Delivery/process findings use repository issue evidence and current retained process surfaces. They establish recurring failure mechanisms, not a claim that every historical issue, branch or validator was individually wrong.

Work remains under [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). V2 runtime, CI, validators, ACTIVE registry and user data are not modified by these documents.