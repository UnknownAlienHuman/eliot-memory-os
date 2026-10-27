# Eliot V3 — One-shot inference contract

**Revision 0.17-draft · 2026-10-27 · shared Memory OS ↔ `eliot-swarm-controller` V2 boundary; not implemented.**

This is the sole normative contract for one-shot text and embedding execution. Memory owns semantic work; controller owns authenticated physical model execution and bounded temporary copies. The boundary does not create a controller Agent, native session, Goal, Task/Attempt/review workflow, automation run, script, generic service-account platform, second receipt store or hidden retry ladder.

## 0. Authority and prerequisites

Inspected controller authority:

```text
UnknownAlienHuman/eliot-swarm-controller
main = 613ea6b5ff6389c7629a988e271477ee45c9d2c1
merged PR #198
```

Controller V2 is specification-only. Issue #200 now owns separation of binding allocation, selected pointer and effect publication; PR #201 is fixture-only. Issue #199 owns this later extension after #200 and V2 L0/L1. No implementation may patch controller V1 to make this contract appear available.

## 1. Ownership

Memory daemon owns:

- finite job, exact sources and coverage;
- processing-method revision and disclosure reduction;
- exact request bytes and every Memory-side external `WriteId`;
- result verification/copy, cognitive decoding/publication and later consumer;
- one controller-mutation owner;
- one backup-set owner, backup IDs, installation records, restore file leases and cleanup;
- backup cut classification and release/retention fences;
- caller-authorized cancel/release requests.

Memory supervisor owns:

- executable/root/process custody;
- disposable candidate Store process/root;
- final installation-selection cutover;
- candidate termination/discard after daemon/channel loss.

Controller owns:

- caller authentication and current-credential fence;
- inference connections/profiles and actual destination;
- global `WriteId` receipt semantics;
- provider invocation/readback;
- private input/result copies;
- call status, retention, erased tombstones and cleanup facts.

Controller owner may install/rotate/disable a Memory principal and perform non-disclosing break-glass erase. Memory never receives owner authority.

## 2. Principal, credential and identity

Controller adds one principal kind:

```text
memory_inference
```

One stable Memory installation maps to:

```text
client_id = memory:<stable-memory-installation-id>
```

Distinct values:

```text
controller_id
client_id
token_version
raw token
```

`client_id` survives Memory restart, Store cutover, rollback and token rotation. Changing it is unsupported principal migration.

Every controller-backed job retains, without secrets:

```text
controller_id
controller_client_id
selected_token_version
inference_write_id
method + canonical request identity
controller_admission_state
controller_admission_seq when admitted
controller_dependency_state
profile/connection/adapter/destination snapshot
result digest/length when present
cancel/release/retention WriteIds and auxiliary states
per-copy cleanup state
```

Call admission state:

```text
prepared
admitted
retired_not_admitted
admission_unknown
```

Auxiliary cut state:

```text
effect_observed
retired_not_sent
mutation_unknown
```

Backup dependency state:

```text
controller_closed
controller_dependent
```

A retired ID can never be sent later.

## 3. Exact controller surface

Authenticated reads:

```text
client.identity
inference.get
inference.list
inference.high_water
inference.result.read
```

Authenticated caller mutations, each with one precommitted global external `WriteId`:

```text
inference.text
inference.embed                 # later
inference.cancel                # own queued call only
inference.release
inference.retention.advance
```

Controller-local owner maintenance:

```text
memory.client.install
memory.client.rotate
memory.client.disable
inference.erase                 # non-disclosing break-glass
```

No method creates or reuses Agent, generation, binding, turn, command, Goal, automation, workspace, native session, Task, Attempt, review or acceptance objects.

## 4. Provisioning and credential publication

A controller-local owner command installs or rotates one principal through the normal owner `WriteId` path. It resolves `controller_id`, commits one exact registration/version transition, derives the raw token from private routing key + client ID + token version under a dedicated domain tag, stores only version/hash and publishes the raw token into one admitted private credential bundle.

The destination is beneath an admitted private directory/handle, no-reparse, restrictive ACL, create-new, file/parent durable and exact-read-back. Arbitrary path write authority is not exposed. Raw token never enters argv, SQLite, receipt result, logs, diagnostics or status.

Lost install/rotate reply retries the same owner WriteId and re-derives the same token. Missing/mismatched routing key blocks issue/reissue.

## 5. Connection identity and stale-credential fence

`client.identity` returns:

```text
controller_id
client_id
principal = memory_inference
token_version
api_version
write_id_floor_ms
write_id_future_skew_ms
```

Memory requires exact equality with installation selection and credential bundle before any application call.

Before every read or mutation, controller reloads registration and requires current enabled principal, exact client ID, exact token version/current hash and unambiguous peer classification. Stale connection receives `credential_stale` and closes after terminal response. A new token version may read/release old calls because ownership is stable client ID.

## 6. Installation-scoped external WriteId generator

External `WriteId` is a globally unique canonical 26-character ULID. Memory owns one locked atomic state outside rollback Store roots:

```text
controller-write-id.state {
  schema_version
  controller_id
  client_id
  last_ulid
}
```

Generation order:

1. authenticate identity and observe controller floor/future skew;
2. lock and reread state;
3. generate a monotonic ULID after retained value and admitted floor/current monotonic time;
4. atomically replace and read back state;
5. persist exact ID in the owning job/maintenance record;
6. only then send.

Crash after advancement burns an ID. Crash before job persistence must not send. Rollback never rolls the file backward. Total state loss is a continuity incident, not permission to replay old jobs under invented IDs.

## 7. Live call identity and replay

Memory persists exact request bytes/digest and call WriteId before first send.

```text
call identity = WriteId + client_id + method + canonical semantic payload digest
```

Canonical payload contains profile, origin, disclosure, input digest/length, response role and finite limits. It excludes transport request ID, pager, wait and client timeout.

```text
existing ID + same identity -> original/current call
existing ID + mismatch      -> id_conflict
valid absent live ID        -> first admission
absent below floor/window   -> id_expired
absent excessive future ID  -> id_future
```

Normal disconnect/restart deliberately repeats the same method, ID and bytes. Provider-send uncertainty remains retained call state. Restore is stricter: an old backup never first-admits an absent call or auxiliary ID.

## 8. Minimal controller state

Reuse V2 `write_receipts`. Add only:

```text
memory_inference_clients
inference_calls
private call-owned inference_input/result files
```

Client registration owns:

```text
last_admission_seq
retain_after_seq
```

Both begin at zero. First admission transaction checks signed-64 exhaustion, increments `last_admission_seq`, inserts receipt/call and retains the allocated sequence. Never derive it from retained rows.

Call row contains WriteId, admission sequence, caller, method, payload digest, frozen profile/connection/adapter/destination, origin/disclosure, input/result metadata/copy states, native request ID when available, last cancel/release identities, terminal code/tombstone and timestamps. Raw input/result/provider error/credentials never enter rows or receipts.

## 9. Profiles, destination and disclosure

Controller owns static `InferenceConnection` and `InferenceProfile` records distinct from Agent profiles. Connection owns adapter/transport, endpoint, provider credential reference and actual destination. Profile owns connection/digest, requested model, automatic-use permission, finite limits and formats.

A loopback gateway forwarding to cloud is external. Memory chooses a profile name only. It cannot supply arbitrary endpoint, headers, extras, retries or fallback.

Memory reduces contributing material to `local_only | external_allowed`. Controller resolves actual destination and checks disclosure before provider I/O. Mismatch or unavailable capacity is operational failure/waiting, not cognitive no-change.

## 10. Controlled input/result copies

One call creates at most:

```text
inference_input
inference_result
```

They are private deterministic call-owned files, not generic artifacts.

For valid absent live ID, controller validates caller/profile/disclosure/limits, durably publishes exact input without replacement, rechecks receipt and atomically inserts receipt + queued call. Orphan input is non-dispatchable cleanup material. A committed row with missing/mismatched input is damaged.

Visible result is one bounded private envelope durably published and verified before settlement. Restart may finish settlement from exact pending envelope. Missing/mismatched settled result is damaged.

Per-copy state:

```text
not_created | retained | cleanup_pending | removed | already_absent | mismatch | unknown
```

## 11. Runner and provider uncertainty

One bounded runner:

1. selects eligible queued call under frozen profile concurrency;
2. verifies input/current registration/profile;
3. CAS `queued -> sending` before provider I/O;
4. performs at most one provider attempt;
5. retains native request/readback identity when available;
6. publishes exact result when present and settles bounded facts;
7. never performs hidden retry, redirect or fallback.

Possible provider send followed by loss becomes `unknown` unless exact native readback resolves it.

## 12. Controller-mutation and backup-set owners

One daemon controller-mutation owner serializes:

```text
inference.text / inference.embed
inference.cancel
inference.release
inference.retention.advance
```

One daemon backup-set owner owns:

- backup ID allocation;
- final backup directory publication;
- installation record scan and state derivation;
- fence/abort/retire transitions;
- controller-dependency snapshots;
- restore read leases;
- physical backup cleanup.

It is an in-process mutex/owner task with retained OS handles, not another service, Store table or workflow engine.

A new fence uses strict order:

```text
close and drain controller-mutation owner
→ enter backup-set transition
→ publish/read back final fence authority
→ leave transition
→ reopen mutation admission
```

Therefore no release or retention advance can pass a stale “no fence” read. Terminal transitions remove pins; stale pre-terminal reads are conservative.

## 13. Backup IDs and atomic first visibility

Backup ID grammar:

```text
b_<32 lowercase hexadecimal characters>
```

It is generated from 128 OS-random bits. It is never derived from Store rollback state or wall clock and never reused after a final fence or terminal marker.

Before any part:

1. build canonical backup plan and digest;
2. create one private same-parent temp directory;
3. write canonical `fence.json` inside;
4. flush fence file and temp directory;
5. atomically no-replace rename temp directory to `backups/<id>` with write-through semantics;
6. flush `backups/` parent;
7. reopen final directory/fence no-follow and verify exact bytes/digest.

Final directory first becomes visible with authoritative fence already inside.

- collision: discard temp, generate a new ID and recompute plan;
- crash before final rename: temp staging is non-restorable/non-pinning cleanup debt;
- possible rename with failed sync/readback: `publication_unknown`; reconciliation opens final name and pins conservatively;
- no reservation row/file/service is added.

## 14. Backup cut, plan and terminal records

Before high-water, Memory stops new controller-backed work, drains controller mutation, pauses replay and dispositions every created call/cancel/release/retention ID.

Every admitted call is classified:

```text
controller_closed
  backup contains every terminal Memory-owned fact/body it needs,
  no future settlement/publication is possible,
  no controller copy/readback/cleanup remains required

controller_dependent
  backup still needs controller state, current/future result bytes or cleanup/readback
```

Canonical plan includes backup ID, expected manifest identity, root/schema/spool cut, controller/client/token/high-water/retain-cut, admitted calls/dependencies, retired attempts, disclosure and gaps. `backup_plan_digest` excludes itself, publication state and later page/part/manifest digests.

Final manifest repeats plan digest plus actual typed table/blob/spool/deletion/config inventories and digests.

Terminal records are create-new, durable and self-contained:

```text
format_version
kind = aborted_before_publish | retired
backup_id
backup_plan_digest
observed_fence_digest
terminal_operation_id
closed reason_code
observed_manifest_digest?   # retire only
```

Abort requires exact fence, no valid manifest, no writer/restore lease, exact partial cleanup and final-manifest absence readback. Retire requires exact published fence+manifest, no abort and no restore lease.

State is terminal-first:

```text
valid standalone retire -> retired/non-restorable
valid standalone abort  -> aborted-before-publish
fence + matching manifest + no terminal -> published/restorable
fence + no valid manifest/terminal      -> preparing/publication_unknown
other malformed/mismatch/ambiguity      -> unresolved/fail closed
```

Terminal marker remains after content cleanup, prevents restore/ID reuse and is not physical erasure.

## 15. Release, retention and erasure authority

`inference.cancel` can cancel only caller's queued call before sending. `inference.release` has one disposition:

```text
memory_copy_verified
terminal_without_result
abandon_for_erasure
```

Before release, mutation owner obtains a current backup-set snapshot and rechecks immediately before send. Any restorable backup or unresolved fence marking the call dependent blocks release.

Controller-owner `inference.erase` is local non-disclosing break-glass. Memory cannot submit it and records owner-action debt until readback.

`retain_after_seq` guarantees complete membership above the cut. Calls at/below cut may prune only when terminal, every copy released/absent and no readback remains. Open/unknown/unreleased calls never prune merely because below cut.

Required cut is the minimum high-water among published non-retired backups and unresolved preparing/publication-unknown fences. In-cut dependencies do not lower the monotonic cut; they stay unreleased. Content erasure above cut leaves bounded text-free membership tombstone until cut advances.

## 16. Restore lease and candidate custody

Restore is admitted only by daemon backup-set owner. It obtains:

- exact logical lease bound to backup ID/plan/manifest;
- retained no-follow handle to final directory;
- retained no-follow handles to fence, manifest and required parts;
- delete sharing denied for leased files;
- final terminal-record recheck immediately before cutover decision.

Retirement, abort and cleanup wait. Supervisor receives only closed backup identity/digests and candidate/cutover intent. It owns candidate process/root but not backup file authority.

Daemon/channel loss while candidate exists requires supervisor to terminate, reap and discard candidate before a new daemon starts or cutover proceeds. Supervisor loss is contained by its Job. A scan without a held lease is not restore authority.

## 17. Restore and stale mirrors

In-cut restored jobs:

```text
controller_closed       restore from backup facts; controller row may be absent
controller_dependent    exact call and required copy must remain
retired_not_admitted    never send old ID
admission_unknown       hold; inference disabled
```

Capture one inventory high-water and page fixed interval `(backup_high_water, inventory_high_water]`. Returned post-cut calls are outside restored cognition. Valid caller uses dependency-aware cleanup; missing caller creates owner-action debt.

Before ordinary job claims, daemon scans installation records, reconstructs backup set/leases, reconciles Store maintenance mirrors and marks future-timeline/unmatched rows `superseded_by_installation_state`. Such rows cannot create fence/terminal records, clear pins or send old release/retention effects.

Any history gap, unknown auxiliary mutation, terminal ambiguity, missing dependent copy or identity reset leaves inference disabled while Base remains usable.

## 18. Rotation and request shapes

Memory selection keeps current, pending and at most one previous credential for exact controller/client/version. Unknown rotation retries same owner WriteId and token derivation. Pending identity must authenticate and read a pre-rotation call before promotion. Previous secret retires only after reconnect, old-call read/release and restart readback.

Initial `inference.text` accepts one bounded exact UTF-8 prompt, digest/length, profile, origin, disclosure, closed response format and finite output/time limits.

Initial adapter is a closed loopback-compatible OpenAI chat-completions subset: one model, one user message, admitted max tokens and optional JSON-object format. No tools, streaming, arbitrary fields, ambient proxy, redirect, hidden retry or fallback. Loopback does not prove local destination.

## 19. Implementation order and evidence

P1a begins only after controller #200 and V2 L0/L1:

1. stable controller identity and scoped client registration;
2. identity/current-token fence;
3. static profile/destination/disclosure admission;
4. WriteId-backed text call and private copies;
5. get/read/cancel/release/high-water/list/retention;
6. tombstones and owner break-glass;
7. Memory external-ID state and mutation owner;
8. daemon backup-set owner, atomic final fence publication and terminal records;
9. call/auxiliary cut and dependency classification;
10. restore lease/candidate crash custody and stale-mirror reconciliation;
11. one episode result copied, decoded, consumed later and eventually released.

P1b adds install/rotate lost-reply reconciliation, stale-session reaping and delayed previous-secret retirement. Embeddings and direct HTTPS are later independent increments.

Required evidence includes:

- same live call ID before send/lost reply/restart;
- no second provider attempt after possible send;
- every external mutation has cut disposition;
- final backup directory never appears without fence;
- pre-rename temp never pins;
- post-rename unknown pins after reconciliation;
- terminal marker remains authoritative after content cleanup;
- restore lease blocks retirement/deletion and final recheck precedes cutover;
- daemon loss discards candidate before restart/cutover;
- dependent call remains unreleased even below current cut;
- fixed inventory returns history gap below retain cut;
- result bytes are exact-caller only;
- one real episode revision changes later context after restart.

## 20. Frozen non-goals

Do not:

- implement this in controller V1;
- use Agent/Goal/automation/script/MCP/CLI subprocess per call;
- accept owner/Agent/no-token fallback;
- invent another Operation/Task/submission ledger;
- add a controller backup-pin service/table;
- derive backup IDs or WriteIds from rollback Store state;
- create an empty final backup directory as reservation;
- make terminal marker depend forever on files cleanup deletes;
- restore without a held lease;
- let Store mirrors create installation authority;
- first-admit absent old IDs from backup;
- release pinned calls or advance retention past pinned high-water;
- let Memory submit controller-owner erase;
- store prompts/results/secrets in receipts/logs/generic artifacts;
- claim provider-side deletion or non-execution from local cleanup.