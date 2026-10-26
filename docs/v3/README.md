# Eliot Memory OS V3

**Layered Base and additive extensions · 2026-10-26 · normative design, not implemented code.**

V1 and V2 are donors. V3 is a greenfield implementation.

## Reading order

1. [Architecture](ARCHITECTURE.md) — purpose, authority owners, Base, extensions and non-goals.
2. [Implementation](IMPLEMENTATION.md) — runtime, IPC, modules, data, Store/durability/maintenance contracts and implementation order.
3. [Cognition](COGNITION.md) — current-work reconstruction, retrieval, learning, consolidation and self-improvement algorithms.
4. [One-shot inference contract](INFERENCE-CONTRACT.md) — sole Memory↔controller boundary for profiles, disclosure, controlled payloads, readback and cleanup.
5. [Active analysis registry](ANALYSIS-REGISTRY.md) — checked evidence, decisions, gaps and next queue.
6. [Audit conclusion](AUDIT.md) — evidence, root causes, rejected machinery and source limits.
7. [Requirements/source map](AUDIT-MAP.md) — stable dispositions for original requirements, audits and donors.

Architecture draft.9, Implementation draft.28 and Cognition draft.11 describe one product at increasing depth. `INFERENCE-CONTRACT.md` is one narrow cross-repository boundary, not another architecture or workflow layer. The complete target is not a prerequisite for useful Base. None of these documents is implemented product code.

`ANALYSIS-REGISTRY.md` is the only active analysis ledger. `AUDIT-MAP.md` is the stable source/decision matrix.

## Selected construction and authority

One local Rust package/codebase provides supervisor, daemon and transient relay modes. One active external SurrealDB child owns persistence; a restore may temporarily use one isolated disposable candidate.

- **Daemon:** application operations, Editor-authenticated Store mutations, replay/jobs, backup cuts, quiesce evidence and external control.
- **Supervisor/installer:** executable/data-root/process identity, root/Owner credential use, migrations, DB-user rotation, Store lifecycle and installation cutover.
- **Controller:** provider credentials and physical model execution.
- **Host/controller:** user task/action execution and acceptance.

Root/Owner material never enters the daemon path. One inherited duplex channel carries only closed maintenance intents/results—never arbitrary SQL, argv, endpoint, path or secret. A request/acknowledgement is not completion; process, credential, Store and selection readback own the result.

Base captures real events, preserves notes/corrections/commitments, supplies exact/lexical context and reopens exact sources after restart. It starts without model, vectors, converter or Research. Extensions reuse the same records/jobs/revisions/context; there is no second Lite/Full memory engine.

## Process and IPC baseline

### Retained launch and root identity

Before an owned child is resumed:

```text
open executable + selected data root + relevant ancestors no-follow
→ verify file/directory identity, protected DACL and bounded SHA-256
→ deny write/delete or root rename sharing as appropriate
→ create child suspended
→ compare child image/file identity
→ assign Job Object
→ resume only after agreement
```

A path, digest, root ID or PID alone is not identity. The retained selected-root lease remains for the Store lifetime.

The installation root is one qualified local fixed NTFS/ReFS volume with a protected current-user+LocalSystem access profile. Databases, source bodies, spool and backups are plaintext application data protected by account/DACL and volume security. Base does not claim application-level at-rest encryption or portable/off-machine backup. Automatic backups remain inside the controlled root.

### Relay→daemon

One installation-scoped Windows named pipe uses first-instance creation, remote rejection, protected DACL and mutual process attestation. Relay verifies daemon PID/start/session/image/file and supervisor Job membership; daemon verifies relay PID/start/SID/session/image. Retained handles bracket PID reuse. One bounded versioned request/response per transient connection. This is not the V2 role/session/lease platform and does not claim to defeat arbitrary malicious same-account code.

### Supervisor↔daemon

Two one-way anonymous pipes form a private inherited duplex channel. Only exact daemon ends appear in `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`; child environment carries handle numbers/protocol generation, not secrets. Closed frames cover Store descriptors, quiesce/resume, maintenance request/result and shutdown readiness. Channel loss is fail-closed. Before cutover a lost daemon abandons the candidate; after possible selection replacement startup reads actual selection before another action.

## SurrealDB baseline

First qualification target: SurrealDB **3.3.4**, external RocksDB, explicit `sync=every`, no fallback.

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

Sanitized environment disables metrics and excludes inherited capability/slowlog/telemetry/Postgres/import/arbitrary `SURREAL_*` settings.

The port is runtime state. A reservation narrows the race; Windows TCP-table observations prove listener and established peer belong to the retained child before credentials. Port/TCP/HTTP/101 alone prove nothing.

Authentication and DB selection occur in Basic-authenticated WebSocket upgrade on the verified stream. RPC signin/use/version/ping are absent. Binary/root/process/peer identity establishes service identity; Ping/Pong supplies transport liveness; only fixed query remains. Origin/CORS is not WebSocket authentication. Anonymous upgrade remains upstream but guest query is denied; Slice 0 measures resource exhaustion.

### Root, Owner and Editor

```text
empty root starts once with one retained root credential in child-only env
→ possible root persistence
→ child stops
→ same root restarts without root env
→ root authenticates on verified peer
→ NS + STRICT DB + Owner + Editor created with PASSHASH
→ checked migrations through Owner
→ root-free restart and role admission
```

Unknown bootstrap reuses the same root credential. Editor is daemon runtime; Owner/root are supervisor-only. No plaintext PASSWORD, credential header, verifier or raw auth error is logged.

### Store transport

One dedicated task owns each authenticated socket, continuously handles control/data frames and permits one in-flight exact ID. Timeout, cancellation ambiguity, wrong/late response, close or protocol fault poisons the socket. Possible mutation send becomes `OUTCOME_UNKNOWN`; reconnect repeats peer/auth admission and application readback.

JSON carries explicit DTOs only: no generic Surreal Value, `SELECT *`, implicit native-type round-trip or copied CBOR tags. Every query has fixed projection/order/bounds and exact decoder.

Store admission is the conjunction of selected-root/executable identity, listener/peer owner, `/ready`, Editor handshake, healthy socket owner, query-only denial matrix, schema/INFO and typed write/read/delete. No relay claims committed capture before daemon admission.

## Local durability and selection

Immutable blob/spool/deletion/backup publication:

```text
create-new same-directory temp
→ full write + file flush
→ no-replace MoveFileExW WRITE_THROUGH
→ parent-directory flush
→ reopen exact bytes/identity
```

Post-rename sync/readback failure is unknown, not staged.

Mutable `installation.toml` is supervisor-only expected-generation replacement with `MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)`, parent flush and exact readback. It carries one current and at most one unretired previous root, and at most one pending/previous credential per role. Another cutover/rotation is blocked until the prior generation is retired. `ReplaceFileW` is not treated as write-through. Possible replacement failure becomes `SELECTION_UNKNOWN`; startup reads actual old/new state.

Previous roots/credentials stay until a separate retirement operation survives restart/readback. A previous root is never directly reselected; recovery goes through typed restore so current deletion fences/config/credentials apply.

## Durable capture and first host

First host: one Claude Code hook relay. Initial events: SessionStart, UserPromptSubmit, PostToolUse/Failure, Stop, SubagentStop, PostCompact, SessionEnd. PreToolUse/permission/finish gates are outside Base.

One immutable `CaptureCommand` is built before IPC. Native/command identity identifies occurrence; digest verifies bytes.

```text
same command → daemon capture → matching Store readback → committed
stage_required/unavailable/uncertain → exact command durable spool → staged
staged command → daemon replay → Store readback → pending removed
```

`stage_required` is private flow control before Store/blob ownership. Public outcomes:

- committed — Store readback matched;
- staged — exact pending file durable;
- unknown — neither ownership established;
- rejected — deterministic pre-ownership exclusion/validation/bound failure.

One daemon replayer. Backup/restore/shutdown/erasure stop new replay and drain/reconcile the active item before taking inventories.

SessionStart/UserPromptSubmit return actual packet content. “Event spooled” is status. Packet retention uses ordinary observations/blobs/links. Prepared, emitted, action-associated and actually used remain distinct.

## Exact open

One exact handle/locator, optional bounded range. Never rerun search/conversion/Research/inference for historical handle. Result states requested/resolved identity, range/digest, current/history, conditions/limits/gaps, revision-aware relation descriptors, expansion/cursor and exact missing/forbidden/erased/damaged/unsupported disposition. Fixed caps need continuation. Historical handle never falls forward.

## Backup, rollback and erasure

Surreal HTTP export/import and startup import are not application owners.

### Backup

Daemon closes mutations/replay, reconciles writes, and cuts versioned canonical typed pages over six tables, selected-root blobs, deletion notices, pending and retained failed spool and sanitized config. Fixed field order and exact-byte digests; manifest owns completion. Manifest carries strictest disclosure. Backup remains under protected local root.

### Restore is exact rollback

Initial restore activates one backup cut after newer deletion fences and exact spool continuity. It does **not** claim merge of later Store rows.

- healthy current Store requires a fresh verified safety backup;
- disaster mode explicitly records uninventoried current state;
- previous root retained; later rows remain there/safety backup until retirement;
- only deletion ledger and pending/failed spool auto-union/merge;
- post-backup rows/jobs/config are not copied silently;
- restored known controller Operations enter reconciliation, never redispatch;
- unresolved out-of-target Operations block or require explicit abandonment;
- restore is blocked while another unretired previous root exists.

Candidate is built/admitted by supervisor with root/Owner. At cutover daemon quiesces writes/replay/jobs and closes old socket; supervisor merges external continuity, replaces selection current=candidate/previous=old, then daemon independently admits selected Store with Editor before resume. Channel loss before replacement abandons candidate; after possible replacement startup reads actual selection.

### Controlled-copy erasure

Deletion ledger prevents reintroduction but is not physical deletion proof. Controlled copies include current and previous roots, candidates, pending/failed spool, selected-root blobs, controlled backups/safety backups and controller/result copies.

Initial Base does not selectively rewrite offline roots/backups. If a previous/candidate root or backup contains erased scope, complete erasure requires deleting that whole generation with bounded traversal/directory durability. If retained, erasure remains incomplete even though current fences prevent reactivation. Off-machine copies are external and reported outside controlled scope.

## Credential rotation and revocation

One pending/previous ref per role. Editor rotation:

```text
create pending secret + durable pending ref
→ quiesce daemon and close old Editor socket
→ fixed PASSHASH mutation through fresh Owner socket
→ unknown probes pending then current; same secret reused
→ promote pending/current/previous selection
→ close privileged sockets and restart SurrealDB
→ daemon authenticates current Editor and repeats admission
→ resume
→ later explicit old-secret retirement after restart/readback
```

Store restart is required because changing stored password alone does not prove revocation of already authenticated WebSocket sessions. Owner follows same pattern. Root rotation is outside first Base.

## Why V2 stalled

Useful goals remained; failure came from turning each principle into its own owner/registry/receipt/lifecycle/proof ceremony and rewarding artifacts over integration. Cheap blockers were checked late; overlapping work lacked one queue owner; documentation/conformance displaced product paths.

V3 uses one live ledger, one integrator/terminal overlap disposition, cheap preflight first, connected completion, retirement of superseded authority and product code before generalized platforms.

## Preserved goals, minimal mechanisms

| Goal | V3 minimum | Not default |
|---|---|---|
| Resume | Stable work address + observations + direct reconstruction | Universal state/checkpoint platform |
| Source/provenance | Observation + blob/range + exact handles | Truth/evidence promotion service |
| Correction | Current revision + history + grounds | Global truth score/ladder |
| Avoid repeats | Scoped negative memory/method revision | Failure-fingerprint platform |
| Context | Exact/current-work + lexical + optional vector + bounded packet | Context service/packet DB |
| Learning | Finite Memory job + exact recipe + one-shot inference + later consumer | Permanent Dreamer/Task lifecycle |
| Optional capability | Internal connected vertical increment | Crate/process/manifest per noun |
| Privacy | Disclosure + actual send-owner check + finite copy cleanup | General Governor/approval platform |
| Recovery | One Store + spool + supervisor + typed backup/exact rollback | Recovery DB/global identity graph |
| Authority | Daemon application owner + narrow inherited privileged boundary | Public supervisor API |
| Method improvement | Outcome linked to exact revision | Intelligence score/model judge |
| Development | One issue/branch/integrator + overlap disposition | Work-unit DB/agent scheduler |
| Verification | Lowest connected distinguishing edge | Shape proof as product completion |

## One-shot model execution

Dreamer is one finite Memory job:

```text
episode + exact recipe + disclosure
→ saved request
→ controller Operation + controlled input
→ exact result when present
→ verified Memory copy
→ decode + ordinary revision/no-change
→ later context
→ release controlled copies
```

No-result is operational, not cognitive no-change. Erasure uses abandon-for-erasure and cannot prove provider-side non-execution/deletion. Controller owns provider execution; Memory owns job/source/recipe/disclosure/copy/decode/publication.

## Development order

0. Exact Windows/Surreal discrimination: executable+root leases/DACL, explicit inherited handles, privileged channel, relay pipe, canonical RocksDB sync=every, sanitized process, dynamic peer ownership, Origin/anonymous bounds, root/Owner/Editor, query-only socket owner, DTOs/conflicts/unknowns, immutable vs mutable files, replay barrier, protected backup/exact rollback with safety/non-merge/restored-job handling, controlled-copy erasure, credential restart/revocation and previous-generation backpressure.
1. Store/lifecycle and exact persistence.
2. Useful Base with one host/context/open/backup/rollback/erase.
3. Controller one-shot inference owner without Task/Attempt.
4. First learning and restore reconciliation for controller Operations.
5. Independent vector/view/document/Research/host increments.
6. Advanced curation after Base paths work.

Production code first. Minimum relevant build/Clippy after coherent increments. Full suite after connected product. Cheap blockers first; one integrator; leaf compile/docs/receipt do not close a slice.

## Evidence limits

Available corpus only; full release ZIP and `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` unavailable. Donor findings apply only to exact paths/revisions in registry; no donor qualified wholesale. Work remains under [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). V2 runtime/CI/validators/ACTIVE/user data are not modified by these documents.