# Eliot V3 — One-shot inference contract

**Revision 0.19-draft · 2026-10-28 · proposed Memory ↔ controller extension; not an available API.**

This document owns only the cross-repository inference boundary. Memory owns semantic
jobs; controller owns authenticated physical calls and temporary copies. Memory's
Store, filesystem backup format and process custody belong to
[Implementation](IMPLEMENTATION.md). Cognitive interpretation belongs to
[Cognition](COGNITION.md#9-controller-backed-job-lifecycle).

## 0. Authority and prerequisites

Source observation, not runtime qualification: controller
`5891cb706d1708bda28b2bd64be6d7996a6e2bdb`, inspected 2026-10-28.

| Existing controller surface | Evidence | Consequence for this extension |
|---|---|---|
| L0/L1 are implemented according to the owning roadmap; L2 is also checked. | [Roadmap](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/5891cb706d1708bda28b2bd64be6d7996a6e2bdb/docs/roadmap.md) | Do not schedule foundation reconstruction. |
| Router principals are Owner and Agent; its dispatch has no `inference.*`. | [Router](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/5891cb706d1708bda28b2bd64be6d7996a6e2bdb/crates/eliot-daemon/src/router.rs#L81-L197) | Memory authentication and every method below are additions, not reusable handlers. |
| Command bindings live in `commands`; other mutations use `writes`. | [API](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/5891cb706d1708bda28b2bd64be6d7996a6e2bdb/docs/spec/api.md#L29-L59), [Store schema](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/5891cb706d1708bda28b2bd64be6d7996a6e2bdb/crates/eliot-store/src/lib.rs#L245-L253) | Reuse that writer and namespace checks; do not invent `write_receipts`. |
| Direct RPC mutation IDs are literal keys; the CLI sends uppercase ULIDs. The API defines no general receipt/floor framework. | Same API section | Memory persists one canonical spelling; no assumed floor-negotiation service. |

[Controller #199](https://github.com/UnknownAlienHuman/eliot-swarm-controller/issues/199)
owns the proposed extension. Its old foundation/binding prerequisites are not the
current capability test. Agent binding allocation from #200 is outside this one-shot
path: no Agent or binding is created here. Do not close or implement #200 on that basis.

Enable inference only after the controller implements and advertises this versioned
surface, scoped credentials and required readback. Missing support is
`inference_unavailable` at the Memory boundary, never an owner-token, Agent, CLI or
legacy-runtime fallback. Base does not wait. Verify a new controller revision before
adopting it; this snapshot does not track a moving `main` automatically.

## 1. Ownership

| Owner | Responsibility |
|---|---|
| Memory daemon | Job, sources/coverage, method revision, disclosure, immutable request, pre-send IDs, verified result copy, publication and later consumer |
| Memory controller-mutation owner | Serializes call/cancel/release/retention and supplies their exact cut dispositions |
| Memory backup-set owner | Installation records and dependency snapshots; prevents releasing copies needed by a backup |
| Memory supervisor | Privileged process/root custody, disposable restore candidate and final cutover |
| Controller | Scoped authentication, profile/destination admission, mutation binding, call state, one provider attempt, private input/result, inventory and cleanup |
| Controller owner | Install/rotate/disable a Memory credential and non-disclosing break-glass erase |

The two Memory owners are in-process responsibilities, not services or new databases.
No Agent, generation, binding, turn, Goal, Task/Attempt, automation or acceptance object
is created for inference. A controller write receipt is not a semantic Memory result.

## 2. Principal, credential and identities

One stable principal represents one Memory installation:

```text
principal kind = memory_inference
client_id      = memory:<stable-random-installation-id>
```

Keep `controller_id`, `client_id`, `token_version` and raw token distinct. Client identity
survives restart, rollback and rotation; token version authenticates, but does not own
calls. Changing controller/client identity is a continuity incident, not an automatic
migration or permission to resubmit old work.

Use the existing private JSON-RPC transport and authentication-envelope shape. The
proposed new `_auth.kind` is `memory_inference`, with exact client/version/credential;
method data remains in `_payload`. JSON-RPC request ID is not a mutation ID. This is a
new Router principal, not a spelling accepted by the inspected implementation.

Before every read or mutation, reload current registration: enabled client, current
version/hash and exact caller scope. Missing, stale or foreign credentials fail closed.
A stale authenticated connection receives `credential_stale` and closes. Private IPC
is not isolation from hostile processes running as the same OS user.

Each job retains nonsecret controller/client identity, selected credential version,
call ID, canonical request digest, admission sequence/state, selected profile snapshot,
result identity, auxiliary mutation IDs and cleanup facts. Do not duplicate the token
or raw provider error into those records.

## 3. Proposed controller surface

All methods in this section are **to be implemented** by #199.

| Caller reads | Purpose |
|---|---|
| `client.identity` | Stable controller/client identity, current credential version and supported inference contract version |
| `inference.get` | Own exact call, state, admission sequence, result metadata and cleanup/dependency facts |
| `inference.write.get` | Read-only lookup of one own inference mutation binding/result; used after lost replies and during backup/restore |
| `inference.high_water` | Own monotonic admission high-water and retained inventory cut |
| `inference.list` | Bounded fixed-window membership inventory |
| `inference.result.read` | Bounded range of one own exact result |

| Caller mutations | Effect |
|---|---|
| `inference.text` | Admit one bounded text call |
| `inference.cancel` | Cancel own queued call before provider sending |
| `inference.release` | Release own controlled copies under an explicit disposition |
| `inference.retention.advance` | Monotonically advance own membership cut |
| `inference.embed` | Later extension; not required for text or Base |

Owner-only maintenance is `memory.client.install`, `memory.client.rotate`,
`memory.client.disable` and non-disclosing `inference.erase`. Memory cannot invoke these
as owner. An owner erase does not grant prompt/result access.

`inference.write.get` reads existing `writes`, not a second journal or generic receipt
service. It returns an exact retained binding/result, a definite absent live ID, or
`history_gap`/unknown when absence cannot be established. It never admits a mutation.
Foreign-principal/method lookup cannot disclose its binding or result. An absent expired
ID is not proof that an old effect never happened. Ordinary retry may resubmit the same
ID; restored backups must use readback, not a mutation as an existence probe.

Every request/response has a closed DTO, exact identity and finite frame, field, page
and range bounds. Validate before allocation/I/O. A receipt lookup result is not permission
to emit private bytes; exact result reads independently authorize the current caller.

## 4. Provisioning and connection identity

Install/rotate follows the controller's owner-authorized non-command mutation path.
It must bind the owner mutation ID to one exact registration/version and private
credential publication. SQLite stores version/hash only; secret bytes remain in an
admitted private credential file, never argv, receipts, logs, status or generic artifacts.

The inspected controller does not establish the old draft's private routing-key or
floor APIs. Do not assume them. Before implementation, #199 must select the exact
secret issuance/recovery mechanism and private-file owner, including lost-reply
reconciliation. Required behavior: retry the same owner ID recovers the same version
and secret publication or reports unknown; it does not mint another secret/version.
Do not add a key hierarchy merely to reproduce the old draft.

Publication requires no-reparse/private ACL, create-new version identity, file/parent
durability and exact readback. Registration cannot become usable before its credential
is recoverably published. Failure preserves the previous usable version or explicit
unknown; it never reports a completed rotation from a hash row alone.

`client.identity` is a proposed scoped read, not owner `daemon.status`. It returns
`controller_id`, `client_id`, principal kind, `token_version` and supported contract
version. Memory compares these to its selected installation before sending application
work. No `write_id_floor_ms` or `write_id_future_skew_ms` service is assumed.

## 5. External mutation IDs and replay

Here `WriteId` means the controller's external mutation ID, not an assumed Rust type.
Memory generates a canonical uppercase ULID and retains that exact spelling. It never
normalizes an already submitted ID differently on retry.

One locked state file outside rollback Store roots retains schema, controller/client
identity and last ULID. Before sending: read current state, generate a later ID using
OS randomness and the local monotonic generator, atomically persist/read back the
advance, then retain the ID in the owning job/maintenance record. Only then send.
A crash may burn an ID but cannot authorize an unrecorded send. State loss or clock
incompatibility stops new inference admission until reconciled; never reset the state
from an old Store backup or mint a replacement ID for an unknown effect.

Bind:

```text
mutation ID + authenticated client principal + method + canonical semantic payload digest
```

Behavior-changing payload includes profile, origin, disclosure, exact input digest/length,
response format and finite limits. Transport request ID, output presentation and wait
options are excluded. Apply the current Store's canonical binding and cross-namespace
conflict rules. Do not create an independent normalization or expiration implementation.

Resolve a retained ID before considering new admission. Same binding returns the retained
admission/result; mismatch is `id_conflict`. An absent ID must pass the controller's
current new-write validation, including expiration. Rejection does not authorize changing
an ID whose send outcome is unknown. A retained admission handle and the mutable call
status are separate: `inference.get` supplies current status.

## 6. Minimal controller state and runner

Extend the existing SQLite writer and `writes` table. Add only the state with new owners:

```text
memory_inference_clients   scoped credential, admission allocator, retention cut
inference_calls            physical call and copy/readback state
private call-owned input/result files
```

A single Store transaction resolves `commands`/`writes` namespace conflicts, checks
principal/payload/capacity, checks signed-64 exhaustion, advances the client's monotonic
`last_admission_seq`, and inserts the write binding plus call. Do not call a standalone
receipt writer and insert the call in a later transaction. Exact replay allocates nothing;
pruning does not reset the allocator. Receipt result contains only bounded nonsecret
admission/effect metadata, not a prompt, result body or provider diagnostic.

Publish exact private input before any provider I/O. The bounded runner verifies it,
current registration and the frozen admitted profile, then durably changes
`queued -> sending` before at most one provider attempt. External I/O never holds the
Store transaction. On restart, `sending` without conclusive native readback is `unknown`,
not permission to retry. No hidden retry, redirect or model/account fallback.

A result becomes readable only after complete private publication and exact digest/length
readback. Failed/partial publication remains explicit. Per-copy state distinguishes
`not_created`, `retained`, `cleanup_pending`, `removed`, `already_absent`, `mismatch` and
`unknown`. Controller restart must reconstruct admitted work without repeating an
uncertain provider attempt.

## 7. Profiles, destination and disclosure

Controller owns the actual destination, credential reference, selected model, allowed
formats, automatic-use policy and finite limits. Memory supplies a selected profile name,
not an arbitrary endpoint, headers, provider extras or fallback list. This extension must
reuse the controller configuration owner where applicable; Agent launch profiles are
not silently executable inference profiles.

Memory reduces contributing material to `local_only | external_allowed`. A derived
representation cannot widen a stricter source it still reveals. Controller checks the
actual destination before I/O; a loopback gateway forwarding to cloud is external.
Mismatch, missing capacity or unsupported format is operational failure/waiting, never
cognitive no-change.

The initial proposed adapter is a bounded non-streaming chat-completions subset: one
selected model and exact UTF-8 prompt, finite output/deadline and an admitted response
format. No tools or arbitrary fields. Its exact wire mapping, limits and credential
source require selection in #199 before enabling it; the existing Codex Agent plugin is
not an implicit implementation or fallback. Embeddings are independent later work.

## 8. Memory backup interaction

[Implementation §8](IMPLEMENTATION.md#8-backup-set-owner-and-lifecycle) solely owns the
filesystem format, first visibility, terminal records, restore leases and candidate
custody. The controller neither interprets backup files nor maintains backup-pin tables.
This section owns only the external-effect cut.

Before a backup high-water, Memory stops new controller-backed work, drains its mutation
owner and dispositions every created call/cancel/release/retention ID through readback:

```text
call:       admitted | retired_not_admitted | admission_unknown
auxiliary:  effect_observed | retired_not_sent | mutation_unknown
```

A retired ID is never sent later. Unknown admission/effect is not empty history.
Every admitted in-cut call is:

```text
controller_closed
  backup contains every terminal Memory fact/body it needs;
  no later settlement/publication or controller readback/copy/cleanup remains

controller_dependent
  controller state, result/copy or cleanup/readback is still needed
```

Keep mutation admission closed through the backup-set owner's final fence publication
and exact readback. Release/retention cannot pass a newly visible fence. The backup plan
records controller/client identity, selected credential version, high-water, retained
cut, admitted dependencies, retired IDs and unknowns. The physical record codec is not
duplicated here.

## 9. Release, retention and erasure

Cancel applies only before provider sending. Release dispositions are
`memory_copy_verified | terminal_without_result | abandon_for_erasure`. A release is a
new ID bound to the exact call/disposition; it does not repeat the original provider call.
The Memory mutation owner rechecks the backup-set dependency snapshot immediately before
send. A restorable backup or unresolved fence depending on that call blocks release.

`retain_after_seq` guarantees complete call membership above the cut. Calls at/below it
may prune only after terminal settlement, released/absent copies and no remaining
readback. Open/unknown/unreleased calls cannot be pruned merely because they are old.
Erasing content above the cut retains a bounded text-free membership tombstone.

The maximum safe requested cut is the minimum high-water of published non-retired
backups and unresolved fences. With no such backups, advance no further than an observed
controller high-water after classifying current calls. Never lower the monotonic cut;
older in-cut dependencies remain protected by the no-release/no-prune rule.

Auxiliary write bindings needed for unresolved cleanup or a retained backup must also
remain readable, or return explicit `history_gap`; generic pruning must not fabricate
absence. Define this retention in the existing writer, not another receipt store.

Owner break-glass erase is non-disclosing. Missing caller authority leaves owner-action
debt until observed cleanup readback. Local cleanup neither proves provider-side deletion
nor proves that an unknown provider call never ran.

## 10. Restore and stale mirrors

Restore preserves the current installation's external-ID state and reconciles its
current backup-set records before job claims. Store maintenance rows are mirrors; a
restored row cannot create a terminal record, clear a pin or replay a stale mutation.

```text
controller_closed       restore from exact backup facts; controller row may be absent
controller_dependent    require exact call and necessary copies/readback
retired_not_admitted    never send that old ID
admission_unknown       hold inference until reconciled
```

Capture one inventory high-water and page `(backup_high_water, inventory_high_water]`
with a cursor bound to client, interval and query version. Do not adopt post-cut results
as restored cognition. Read old auxiliary IDs with `inference.write.get`, never by
first-admitting an absent mutation. Recompute still-needed effects from current call,
backup set and controller cut; only after reconciliation can a genuinely new effect
receive a new ID.

Missing identity, inventory history, dependent copy, unresolved auxiliary mutation or
terminal ambiguity keeps inference disabled. Base remains available unless its own
Store/restore invariant independently prevents it. Valid caller can perform bounded
cleanup; missing caller requires owner action, not impersonation.

## 11. Result use and credential rotation

Memory range-reads an exact result, verifies digest/length, durably copies it, decodes a
purpose-specific schema and atomically publishes accepted revisions. Operational failure,
partial output and decode failure cannot become `no_change`. A useful revision may be
consumed while explicitly recorded cleanup debt remains.

Rotation preserves client ownership of old calls. Keep current, pending and at most one
previous credential selection; reconcile the same owner mutation ID after loss. Before
promotion, the pending version must authenticate and read a pre-rotation call. Retire the
previous secret only after reconnect, old-call read/release and restart readback. A stale
version must never authorize new provider I/O.

## 12. Implementation order and remaining decisions

There is no foundation/#200 gate for this extension. There is a capability gate: the
scoped principal, admission transaction, private result/copy path and recovery operations
above must exist before Memory enables inference.

1. Select the closed DTOs/limits, credential publication/recovery and one actual profile/
   adapter in #199; extend current authentication and Store writer, not legacy V1.
2. Connect one text call to exact status/result/readback and caller cleanup. Implement
   lost-reply and unknown-send behavior with that path, not as a later framework.
3. Connect Memory's persisted ID/job/result consumer and backup cut/release/retention
   rules before enabling inference on a maintained installation.
4. Complete credential rotation, then independently selected embeddings or other routes.

Unselected credential issuance/recovery and exact adapter/DTO bounds are explicit
pre-implementation decisions, not existing controller capabilities. A doc revision or
completed controller L0/L1 does not resolve them. Runtime work and its checks belong to
the owning repository; this prose change authorizes no controller implementation.

Evidence must distinguish exact same-ID replay, namespace conflict, scoped reads, one
provider attempt, lost-reply readback, fixed-window inventory/history gaps, backup-pinned
release, rollback without resubmission, cleanup and a revision actually consumed later.
Formatting/compile is not that evidence. Full campaigns follow connected implementation.

## 13. Non-goals

No Agent/Goal/automation/CLI subprocess for inference; no owner/no-token fallback;
no replacement binding lifecycle, generic service-account framework, Operation engine,
second mutation ledger, controller backup service or provider fallback ladder.
Do not negotiate an invented mutation floor, derive IDs from rollback state, expose
private content through receipts, replay old absent IDs after restore, release pinned
copies or claim provider erasure from local deletion. Memory's BM25, Surreal catalog and
DDL format are internal Store contracts, not controller protocol requirements.
