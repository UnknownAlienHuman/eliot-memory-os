# Eliot Memory OS V3

**Layered Base and additive extensions · 2026-10-26 · normative design, not implemented code.**

V1 and V2 are donors. V3 is a greenfield implementation.

## Reading order

1. [Architecture](ARCHITECTURE.md) — purpose, authority owners, Base, extensions and non-goals.
2. [Implementation](IMPLEMENTATION.md) — runtime, IPC, modules, data, Store/durability/maintenance contracts and implementation order.
3. [Cognition](COGNITION.md) — current-work reconstruction, retrieval, learning, consolidation and self-improvement algorithms.
4. [One-shot inference contract](INFERENCE-CONTRACT.md) — sole Memory↔controller boundary for connections, profiles, disclosure, controlled payloads, readback and cleanup dispositions.
5. [Active analysis registry](ANALYSIS-REGISTRY.md) — checked evidence, decisions, gaps and next queue.
6. [Audit conclusion](AUDIT.md) — evidence, root causes, rejected machinery and source limits.
7. [Requirements/source map](AUDIT-MAP.md) — stable dispositions for original requirements, audits and donors.

Architecture draft.9, Implementation draft.27 and Cognition draft.11 describe one product at increasing depth. `INFERENCE-CONTRACT.md` is one narrow cross-repository boundary, not another architecture or workflow layer. The complete target is not a prerequisite for useful Base. None of these documents is implemented product code.

`ANALYSIS-REGISTRY.md` is the only active analysis ledger. `AUDIT-MAP.md` is the stable source/decision matrix; new work updates the registry rather than creating another chronological report.

## Selected construction and authority

One local Rust package/codebase provides supervisor, daemon and transient relay modes. One active external SurrealDB child owns persistence; a restore may temporarily use one isolated disposable candidate. Ordinary modules retain dependency direction without requiring a process, actor, contract crate or pass-through service per concept.

Authority is split at the physical failure boundary:

- the **daemon** owns application operations, Editor-authenticated Store mutations, replay/jobs, backup cuts, quiesce evidence and the external control surface;
- the **supervisor/installer** owns executable/process identity, root/Owner credential use, migrations, DB-user rotation, Store-child lifecycle and installation selection/cutover;
- root and Owner material never enter the daemon path;
- one inherited duplex channel carries only closed typed maintenance intents and results—never arbitrary SQL, argv, endpoint, path or secret;
- a privileged request or acknowledgement is not completion; exact process, credential, Store and selection readback own the result.

Base captures real host/source events, preserves explicit knowledge/corrections/commitments, supplies exact/lexical context and reopens exact sources after restart. Its maintenance covers the data it actually retains. Base starts without controller, model, encoder, converter or Research credentials.

Learning, vectors, project understanding, documents, Research and additional hosts are independent vertical extensions. They reuse the same records, finite jobs, revision publication, context assembly and maintenance path. A missing extension does not disable Base; disabling a producer does not erase retained readable knowledge. There is no second Lite database or Full memory engine.

## Process, IPC and Store baseline

V3 does not assume that naming an executable, pipe, port, SDK or database makes identity and durability correct.

### Retained launch identity

Before either owned child is resumed, the supervisor:

```text
opens executable + relevant ancestors no-follow
→ denies write/delete sharing
→ streams exact SHA-256 through a bounded buffer
→ creates child suspended
→ compares child image/file identity
→ assigns the owned Job Object
→ resumes only after agreement
```

A path, pre-launch digest or PID alone is not launch identity.

### Relay→daemon

Relay traffic uses one installation-scoped Windows named pipe:

- first instance, so a pre-existing name blocks instead of becoming a second daemon;
- remote clients rejected;
- protected current-user+SYSTEM DACL;
- relay verifies daemon PID/start/session/image/file identity and supervisor Job membership;
- daemon verifies relay PID/start/SID/session/image identity;
- retained process handles bracket the observations against PID reuse;
- one bounded versioned length-prefixed request and correlated response per transient connection.

This is a narrow local boundary, not the V2 role/session/lease/token platform. It excludes pipe squatting, other users, stale generations and unrelated local binaries. It does not claim to defeat arbitrary malicious code already executing as the same Windows account.

### Supervisor↔daemon

The supervisor creates two one-way anonymous pipes before daemon launch and passes only the exact daemon ends through `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. The child-only environment carries handle numbers and protocol generation, not secrets. One owner on each side handles a closed finite vocabulary such as Store descriptors, maintenance requests/results, quiesce/resume and shutdown readiness.

Channel loss is fail-closed. Before selection replacement, a lost daemon causes the supervisor to abandon the disposable candidate. After a possible replacement, startup reads the actual installation selection and reconciles it before another action.

### SurrealDB

The first qualification target is SurrealDB **3.3.4** with external RocksDB and explicit `sync=every`. There is no silent fallback to SurrealKV, another version, root or URL spelling.

The exact child profile is equivalent to:

```text
surreal start <supervisor-derived-canonical-rocksdb-url>?sync=every
--bind 127.0.0.1:<per-start-owned-port>
--deny-all
--allow-arbitrary-query system
--deny-arbitrary-query guest,record
--allow-http rpc
--allow-rpc query
--no-defaults
--no-identification-headers
--client-ip none
--allow-origin <reserved origin; CORS metadata only>
```

The supervisor provides a sanitized environment: metrics explicitly disabled; inherited capability, slow-query, telemetry, Postgres, import and arbitrary `SURREAL_*` settings excluded.

The loopback port is runtime state, not identity. A reservation narrows the bind race, then Windows TCP-table observations must prove both the listening owner and the established server peer belong to the retained child before credentials are sent. Port, TCP success, HTTP status and WebSocket `101` alone prove nothing.

Authentication and database selection occur in the Basic-authenticated WebSocket upgrade on the already verified raw stream. RPC `signin`, `use`, `version` and `ping` are not selected:

- exact binary/process/listener/peer identity replaces RPC version as service identity;
- WebSocket Ping/Pong supplies transport liveness;
- only fixed `query` remains.

`--allow-origin` is not WebSocket authorization. SurrealDB's CORS middleware adds response headers but does not reject the RPC upgrade by Origin. Anonymous upgrade remains possible upstream; guest query is denied, and Slice 0 must measure connection-exhaustion behavior. WSS or a narrow authenticated proxy is considered only if measured local bounds require it.

### Root, Owner and Editor

For local Store credentials, Windows Credential Manager is the secret authority.

Root bootstrap is short-lived:

```text
empty root starts once with one retained root credential in child-only env
→ root may persist
→ child stops
→ same root restarts without root env
→ root authenticates on verified peer
→ NS + STRICT DB + Owner + Editor created with PASSHASH
→ checked migrations run through Owner
→ restart without root env and full role/readback admission
```

An unknown bootstrap reuses the same retained root credential; it never generates a replacement password after root may exist.

- Editor is the daemon's ordinary runtime account.
- Owner is supervisor-only for migrations, user rotation and typed restore.
- Root is supervisor/bootstrap-only.
- Credential headers, DDL buffers, verifiers and raw auth errors are never logged.

### Store transport

Memory uses a small bounded JSON WebSocket client, not the current Rust SDK or V2 Store adapter. One dedicated task owns each authenticated socket, continuously handles control/data frames and allows one in-flight exact response ID. Timeout, cancellation ambiguity, wrong/late response, close or protocol fault poisons the socket. A late reply can never satisfy the next request.

A mutation possibly sent before such failure becomes `OUTCOME_UNKNOWN`; reconnect repeats peer/auth admission and application identity readback before retry.

JSON carries only explicit application DTOs. V3 forbids:

- generic Surreal `Value` decoding;
- `SELECT *` as persistence/backup format;
- implicit native ID/time/optional-value round-trip;
- copied Surreal CBOR tag protocol.

Every fixed query has an explicit projection, stable application IDs, integer time plus precision, explicit optional-state representation, finite vectors and an exact decoder.

Store admission requires the conjunction:

```text
exact binary + retained launch identity
→ listener owner + established peer owner
→ upstream /ready
→ Editor Basic handshake
→ healthy socket owner
→ query-only route/method/subject/function denial matrix
→ schema generation + INFO verification
→ bounded typed write/read/delete through production client
```

No relay may claim committed capture before daemon admission completes.

## Local durability and installation selection

Immutable blob/spool/deletion/backup publication uses:

```text
create-new same-directory temp
→ complete write + file FlushFileBuffers
→ no-replace same-volume MoveFileExW with WRITE_THROUGH
→ parent-directory FlushFileBuffers
→ reopen and verify exact identity/bytes
```

Rename followed by failed directory sync/readback is post-commit unknown, not staged. Reconciliation verifies the actual final path. `MOVEFILE_REPLACE_EXISTING` is forbidden for immutable publication.

The mutable installation selection is a distinct supervisor-only operation. `installation.toml` carries a monotonic generation, current/previous closed root IDs and current/pending/previous non-secret credential references. Replacement uses a fully written/flushed temp, `MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)`, parent-directory flush and exact generation/root/digest readback. `ReplaceFileW` is not used as a write-through primitive. A possible replacement with failed readback is `SELECTION_UNKNOWN`; startup reads the actual selection before any retry.

Previous roots and credentials remain until a later explicit retirement operation survives restart/readback. A successful cutover does not authorize immediate deletion.

## Durable capture and first host

The first integrated host profile is one Claude Code hook relay because it supplies real lifecycle, prompt, tool-result and final-response boundaries. Claude-specific JSON is an adapter input, not the Memory domain model. Other hosts arrive later through the same operations.

The initial event profile is deliberately small:

| Event | Base purpose |
|---|---|
| `SessionStart` | Reopen exact continuation and return real bounded context on startup/resume/clear/compact/fork |
| `UserPromptSubmit` | Capture submitted input and return decision-time context |
| `PostToolUse` | Preserve successful tool call, native ID, input and result |
| `PostToolUseFailure` | Preserve started tool failure/interruption facts |
| `Stop` | Preserve main agent's final host-supplied message |
| `SubagentStop` | Preserve final subagent response and native identity |
| `PostCompact` | Preserve compact summary as derived representation, never replacement source |
| `SessionEnd` | Preserve lifecycle boundary and reason |

`PreToolUse`, permission and stop enforcement are not Base memory requirements. Negative memory is advisory by default. Any later guard is explicit, narrow and opt-in.

### One command and four public outcomes

The relay builds one complete bounded immutable `CaptureCommand` before any daemon call. Native/command identity identifies an occurrence; content digest verifies bytes and never merges separate occurrences.

```text
same command bytes + same command ID
→ direct daemon capture
→ matching Store readback
→ committed

stage_required / unavailable / uncertain direct result
→ exact same command durably published to pending spool
→ staged
→ daemon replays same capture
→ matching Store readback
→ pending removed
```

`stage_required` is private flow control returned before Store/blob ownership while mutation admission is closed. It is not a fifth public result and never maps to rejection.

Public results mean exactly:

- `committed` — Store owns the observation and readback matched;
- `staged` — exact command is durably present in pending spool;
- `unknown` — neither Store commit nor spool publication is established;
- `rejected` — deterministic exclusion/validation/bound failure before ownership; temporary quiesce is not rejection.

The daemon is the only automatic replayer. Backup, restore cutover, shutdown and erasure pause new replay and drain/reconcile the active item before taking Store/spool facts. An unresolved possible Store mutation blocks the operation.

### Context is content

`SessionStart` and `UserPromptSubmit` return actual rendered packet text through the supported host channel. “Event spooled” is status, not context.

Packet retention uses ordinary observations/blobs/links, not a PacketStore. Keep distinct:

```text
prepared
→ emitted through host contract
→ associated with later action when observable
→ actually used/influential: usually unknown
```

Capture survives context failure. The first implementation must qualify the installed Claude version and actual payload/output/timeout behavior.

## Exact open and bounded reads

`open` requires one exact handle or locator and optional bounded range. It never reruns search, conversion, Research or inference to satisfy a historical handle.

Every exact read reports:

```text
requested handle/revision/range
resolved identity/representation
returned byte/item range + digest
current/history state
material conditions, limitations and capture gaps
revision-aware relation descriptors + expansion handles
next cursor
missing | forbidden | erased | damaged | unsupported
```

A current handle does not silently substitute history; a historical handle never falls forward. A fixed relation cap without continuation is incomplete. Ranges/cursors bind to the exact object/revision/representation/options. Large text/blob reads are metadata/excerpt first, then exact ranges with UTF-8 boundaries and real row/byte/element/rendered-text units.

## Backup, restore and erasure

Surreal HTTP export/import and startup import are not the V3 application owner. HTTP export can report success before its job ends; import is statement-by-statement and can leave partial state.

### Backup

The daemon closes application mutations and replay, reconciles admitted writes, cuts canonical typed pages over six tables, exact selected-root blobs, deletion notices, pending and retained failed spool and a sanitized configuration snapshot. Pages use versioned canonical JSON Lines with fixed DTO field order and exact-byte digests. A manifest owns completion.

### Restore is rollback, not hidden merge

The initial restore activates the exact application state of a selected backup cut after applying newer monotonic deletion fences and external spool continuity. It does **not** claim to merge Store rows committed after that backup; no retained change log/conflict policy exists to prove such a merge.

Consequences:

- when the current Store is healthy, a fresh verified safety backup is required before rollback cutover;
- disaster recovery without it is explicit and records that current committed state could not be inventoried;
- the previous root remains retained after cutover, so post-backup rows remain recoverable there or in the safety backup;
- current/newer deletion notices dominate backup content;
- pending/failed spool merges by exact command ID/bytes/disposition; current entries survive and failed never becomes pending;
- completed post-backup Store rows/jobs/config are not silently copied into the restored timeline;
- unresolved controller Operations outside the target backup block cutover until terminal/released or explicitly abandoned.

The supervisor prepares and admits one isolated candidate with root/Owner, while the daemon remains the source of current Store/spool/deletion/quiesce facts. At cutover:

```text
candidate fully verified and restarted
→ supervisor requests quiesce
→ daemon drains writes/replay and closes active socket
→ supervisor verifies cut facts, stops old Store and merges external spool/deletion continuity
→ installation selection atomically replaces current root and retains previous root
→ daemon independently admits selected Store with Editor
→ resume application mutations and replay
```

Channel/daemon loss before selection replacement abandons the candidate. Possible loss after replacement is reconciled from actual `installation.toml`; no blind retry or assumed rollback.

### Erasure

A monotonic deletion notice closes affected mutation/replay admission, drains possible writes, fences unresolved controller work and prevents late Store/Research/spool reintroduction. Restore unions current deletion notices with backup notices; an older backup cannot revoke a later erasure. Complete erasure is not claimed while any controlled copy, backup, spool entry or external-operation cleanup remains unresolved.

## Credential transitions

Editor/Owner rotation is supervisor-owned:

```text
create one pending Credential Manager secret
→ durably record pending reference
→ fixed PASSHASH mutation through privileged socket
→ probe pending/current after unknown outcome
→ promote pending to current, retain old as previous
→ daemon reconnects Editor when relevant
→ restart/readback
→ later explicit retirement of old secret
```

A retry reuses the same pending secret. If neither/both credentials violate the expected transition, rotation blocks with all references retained. Root rotation is not part of first Base and is not improvised through startup credentials.

## Why V2 stalled and what V3 forbids

The useful goals were not the main problem. Continuity, correction, provenance, negative memory, project understanding, Dreamer, privacy, recovery and operator control remain. Failure came from turning each principle into its own owner, registry, receipt, lifecycle and proof ceremony, then rewarding artifacts instead of integration.

Repository evidence adds another causal layer: cheap blockers were checked after expensive preparation; overlapping branches/PRs lacked one queue owner; new sibling work opened without backpressure; documentation/conformance output displaced connected product paths.

V3 therefore uses:

- one live analysis ledger;
- one semantic/integration owner and terminal disposition for overlap;
- cheap admission/configuration checks before setup/agent dispatch;
- completion only for caller→operation→durable result/typed unknown→consumer→restart/readback;
- replacement/retirement of superseded authority instead of append-only clarification;
- connected product code before generalized workflow/plugin/policy/proof infrastructure;
- merged behavior and closed blockers—not prose, LOC, commits, agents or issues—as progress.

## Preserved goals, minimal mechanisms

| Preserved goal | V3 minimum | Not carried forward by default |
|---|---|---|
| Resume work | Stable work address, retained observations and direct reconstruction | Universal Understanding State or mandatory checkpoint protocol |
| Preserve source | Observation + immutable blob/range + exact handles | EvidenceAtom/Truth Registry/promotion service |
| Correct memory | Versioned current item, history, grounds and applicability | Global truth score/promotion ladder/correction subsystem |
| Prevent repeated mistakes | Scoped negative memory or method revision returned by normal retrieval | FailureFingerprint platform or experiment campaign |
| Deliver context | Exact/current-work lookup, lexical candidates, optional vector arm and bounded packet | Context Compiler service or packet database |
| Learn from episodes | Finite Memory job, exact recipe, one-shot inference, typed result/no-result and later consumer | Permanent Dreamer or controller Task/Attempt for one completion |
| Add optional capabilities | Internal module and connected vertical increment | Crate/process/manifests/hot-swap platform per noun |
| Protect privacy | Disclosure propagated with content; authoritative send-owner check; finite copy cleanup | General Governor/approval/capability platform |
| Recover | One Store, source spool, supervisor, typed backup/exact rollback and idempotent readback | Recovery database or global identity graph |
| Keep authority explicit | Daemon application owner + narrow inherited privileged boundary + authenticated externals | Public supervisor API or receipt-backed authority for every in-process call |
| Improve methods | Outcome linked to exact method revision and later revised method | Intelligence score or compulsory model judge |
| Coordinate development | One issue/branch/integrator and terminal overlap disposition | Work-unit database, branch manager or agent scheduler |
| Verify product | Lowest connected edge that distinguishes the property | Shape/module proof counted as product completion |

A mechanism enters V3 only after its real caller, owner, retained result and consumer are named.

## Model execution without another task manager

Dreamer is the cognitive role of a finite Eliot learning job.

```text
retained episode + exact recipe + disclosure
→ saved exact Memory request
→ authenticated controller IPC
→ one inference Operation + controlled input
→ exact result artifact when present
→ verified Memory copy
→ purpose-specific decode
→ ordinary memory revision or valid no-change
→ changed later context
→ inference.release(memory_copy_verified)
```

A terminal no-result is an operational outcome, not cognitive no-change, and cleans the retained input through `terminal_without_result`. Physical erasure of unresolved work uses `abandon_for_erasure`, which fences future controller dispatch/settlement/publication but cannot prove provider-side non-execution or deletion.

`eliot-swarm-controller` owns provider credentials and physical execution. Memory owns jobs, source coverage, recipe, disclosure reduction, result copy, decoding and publication. Real software-agent work with tools may still use controller Tasks; one memory extraction does not justify importing that task system.

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

Every capability needs a real input, operation, retained result or typed unknown and consumer. A stored type, receipt, fixture or generated card is not product behavior.

## Development order

[Implementation §14](IMPLEMENTATION.md#14-implementation-sequence) defines connected slices:

0. Exact Windows/SurrealDB discrimination: retained executable launch and inherited handle list; mutually attested relay pipe; privileged supervisor channel; canonical RocksDB `sync=every`; sanitized process; dynamic listener/peer ownership; Origin non-authority and anonymous-socket bounds; peer-verified Basic query-only transport with cancellation-safe socket owner; reconciled root bootstrap; Owner/Editor `PASSHASH`; typed DTOs; transaction/WAL unknowns; immutable publication vs mutable selection replacement; replay barrier/`stage_required`; canonical backup/exact rollback with safety backup, deletion/spool continuity and explicit non-merge; credential rotation; graceful/forced shutdown.
1. Store/lifecycle and exact persistence.
2. Useful Base with one host, retrieval/context/source open and Base maintenance.
3. Controller one-shot inference owner without Task/Attempt.
4. First Memory learning path and restore handling for unresolved controller Operations.
5. Independent vector, project-view, document, Research and host increments.
6. Advanced curation/diagnosis after Base paths work.

Write production code first. Run minimum relevant build/Clippy after coherent increments. Do not build a speculative test platform or distort production code to satisfy placeholders. The full automated suite follows connected product implementation.

For every slice, resolve cheap blockers first, keep one integrator and give overlapping work terminal disposition before opening sibling work. Leaf compilation, generated documentation or stored receipt does not close a slice.

## Evidence limits

The audit conclusion covers the available corpus and records explicit exclusions. Full release ZIP contents and `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` were not available as readable source material. Donor findings apply only to exact paths/revisions recorded in the registry; no donor is qualified wholesale.

Delivery/process findings establish recurring failure mechanisms, not that every historical issue, branch or validator was individually wrong.

Work remains under [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). V2 runtime, CI, validators, ACTIVE registry and user data are not modified by these documents.