# R13 provider #1 — admission and semantic-resolution boundary

Status: `ACCEPTED_SOL_BOUNDARY`

Implementation state: `R13_1A_STATIC_CONTRACTS_COMPLETE_DYNAMIC_ADMISSION_BLOCKED`

Authority: Root / Sol under `ROOT-DIRECTIVE-v1.5.md` §2, §7 and §9,
Recovery Program §5.1 rule R13, and normative Implementation “Session attach”.
Accepted on 2026-08-26 against:

- source revision `f39d9cfbc084444775ce4802462fbe5b9a0e7ff6`;
- `ROOT-DIRECTIVE-v1.5.md` SHA-256
  `C12C3B15229286B887483BAE4B2B1CD8023F243897E84F77855D891EBE1E7BB4`.

Lifecycle amendment accepted on 2026-08-26 against source revision
`73f916fed1a615ede011b3808c73cebf3e68b731`: the candidate-carried value is a
static, generation-scoped admission **profile**, not a per-logon or
per-process ticket. Interactive session id, connection challenge/nonce and
live PID/start/image evidence belong to a later Kernel-owned connection seal.
Changing any of those values must not require a new Kernel candidate digest or
activation permit.

Materialization-owner amendment accepted on 2026-08-26 against source revision
`a01c6f1b5fbb57a86c7ff80a5ea58e929faab874` and
`ROOT-DIRECTIVE-v1.5.md` SHA-256
`03CDF24EE6B595CC488A916F99C06727AAE4F6BC524800BD4166FC3DB2463AE7`.

This record selects ownership and packet order. It does not claim that the
provider, an authenticated agent Session, D1 ingress, Product Pulse, or the
Goal is complete.

## Decision

The server string `eliot.agent-bridge.activate` is not, by itself, provider
number 1. The first R13 provider is production-reachable only when one real
bridge process can pass the Host/Kernel transport admission boundary, send an
identity-bound activation request, reach a closed Kernel selector and receive
one typed reply.

The normative attach chain remains unchanged:

```text
agent bridge
→ Kernel authenticates the local process/profile and transport generation
→ eliotd resolves principal, WorkScope, task and current plan
→ Kernel issues the generation-bound Session and fence
→ agent receives the exact bootstrap binding.
```

The implementation is therefore split into causal prerequisites inside R13
provider #1. This does not reorder any consumer after R13:

1. **Transport admission.** Host/installation owns a protected, versioned,
   generation-scoped `AgentBridgeAdmissionDescriptor` (a static profile).
   Kernel combines that profile with a fresh per-connection challenge and
   handle-bound OS peer observation, then seals a connection-scoped admission
   receipt. The existing `eliotd` policy remains exact and unchanged.
2. **Reachable server operation.** A neutral wire contract and Kernel selector
   admit `eliot.agent-bridge.activate` only for that bridge profile and a valid
   pre-activation `RequestIdentity`. Kernel rejects malformed,
   unauthenticated, stale, mismatched and fenced requests at their owning
   boundary. Specifically, if semantic resolution is unavailable, the real
   route returns a typed `Denied` with no partial binding; it does not return a
   fabricated `Authenticated` value.
3. **Semantic resolution.** `eliotd` owns one read-only
   `AgentActivationResolver` API over one coherent Governor snapshot. It joins
   the existing state owners and rejects disagreement; it does not create a
   second task, session, WorkScope or plan store.
4. **Session/fence issuance.** Kernel alone binds the resolver decision to the
   authenticated transport generation and issues the generation-bound Session
   and bridge `FencingToken`. `eliotd` never issues a Kernel token, and Kernel
   never invents semantic fields.

A production-reachable typed-denial route may close only R13 step 1 (“server
operation exists”). It does **not** make provider #1 available, decrement a
consumer blocker, or close R13 step 2. The current unconditional
`KernelAdmissionRequired` returned before the bridge loop is not such a route.

## Ownership selected by this decision

| Boundary | Owner | Required source of truth |
|---|---|---|
| Static bridge admission profile | Host/installation | Protected descriptor bound to the approved installation/generation, stable approved user SID, artifact and policy ceiling; no live session/process fields |
| Dynamic bridge connection admission | Kernel IPC + Windows platform adapter | Fresh Kernel challenge plus OS-observed SID/session/PID/start/image/file evidence, sealed and revoked per connection/session |
| Pipe ACL and peer authentication | Kernel IPC + Windows platform adapter | Host-approved peer profiles and OS-observed SID/session/PID/start/image/Job evidence for each admitted process |
| Activation request/reply wire | `eliot-protocol` | Closed, versioned request, `Authenticated` and `Denied` records shared without a Kernel→surface dependency |
| Semantic principal/session | `eliotd` resolver over Governor owners | Active `CoordinationOwner::AgentSession`, cross-checked with `SessionLifecycleOwner` epoch/fence/lifecycle |
| Task/work unit | `eliotd` resolver over Governor owners | Active coordination work item/lease joined to the canonical `TaskLifecycleOwner::TaskRecord` revision |
| WorkScope | `eliotd` resolver | A current `MATCHED` ScopeBindingGuard receipt; a candidate or the current ZST guard alone is not authority |
| Plan | `eliotd` resolver | One current active-plan binding for the selected task/scope; optional observation evidence alone is not authority |
| Transport Session and bridge fence | Kernel | Admitted peer + resolver decision + matching authority epoch/resource generation/state fence |

The resolver is an authority **boundary**, not a new state owner. Until the
missing WorkScope receipt owner and current active-plan read path exist,
`Authenticated` remains forbidden and the resolver must return a typed denial.

Host/installation owns the protected admission policy, stable approved user SID
and allowed peer profiles. Kernel owns the fresh connection challenge, live OS
peer observation, current operational generation/epoch/fence comparison and
connection seal/revocation. UserBroker is not a prerequisite authority for
bridge admission: making it one would be circular because the bridge is an
approved bootstrap path for UserBroker. A descriptor is an immutable admitted
input; it never replaces Kernel's live evidence or becomes a
mutable-current-fence oracle. `ClientHello` remains a per-connection claim
checked against both sources.

## Admission descriptor contract

The descriptor is separate from the discovery catalogue and from the fixed
Phase-A runtime-child manifest. Discovery proves presence only. Adding the
external bridge to `REQUIRED_PACKAGE_ROLES` or `RuntimeLaunchDescriptor` would
change the installed-child schema and requires a separate migration decision;
this decision does not authorize that shortcut.

The protected static descriptor must bind at least:

- descriptor wire id/version and canonical digest;
- module id `eliot-agent-bridge` and exact executable path/SHA-256;
- approved resource generation, authority epoch and state fence;
- stable approved caller SID plus an explicit policy requiring a live
  interactive session for that SID;
- a per-connection process/image sealing policy; the descriptor carries no PID,
  start time, session id or process nonce;
- allowed capability, privacy and effect sets;
- expected Kernel principal/config snapshot digest;
- immutable inputs for the module-specific protected client template used to
  form a fresh `ClientHello` for each connection.

The descriptor must not store a connection id, interactive session id,
per-connection challenge/launch nonce, PID/start/image observation, reusable
`RequestIdentity`, semantic principal, Session, task, WorkScope, plan, mutable
clock, or mutable current fence. Kernel issues a fresh challenge and seals the
OS-observed connection evidence. The bridge derives a fresh pre-activation
identity per request from that authenticated transport snapshot and the
server-provided bounded clock. Its semantic session/task fields remain `None`;
the activation payload carries correlation and attach intent, not
caller-selected semantic identities.

The protected client declaration is likewise a static generation template. It
must not embed a reusable `ClientHello`, connection id or launch nonce. The
bridge forms a dynamic `ClientHello` from the protected module/generation/policy
fields plus the fresh connection challenge; that challenge is correlation, not
authority.

## Accepted materialization owner and source

Root selects the separate-record branch for R13.1a. The bridge remains an
external module and is **not** added to `REQUIRED_PACKAGE_ROLES`,
`CandidateManifest` or `RuntimeLaunchDescriptor`. Its admission input is a
distinct immutable `AgentBridgeInstallationProfile` owned by the installation
transaction and materialized by Host during the same Phase-B transaction that
produces the current authority overlay. Absence of that profile preserves the
legacy `None` carrier but cannot satisfy the R13.1a exit proof.

The installation caller must supply an explicit retained external-module
artifact and an OS-resolved stable user SID. Discovery catalogue entries,
ambient current-user state, account-name text and caller-claimed artifact
digests are not authority. The installation adapter retains and hashes the
source executable, stages it below the protected installation root at
`external-modules/eliot-agent-bridge/<generation>/eliot-agent-bridge.exe`, and
binds the observed file identity, exact destination and SHA-256 into the
profile plan. The SID is the canonical SID returned by the Windows account
resolver for the explicitly selected interactive account; Host and Kernel
never derive it from `WTSUserName` alone.

The protected record pair is derived below the existing Host state root, not
from caller-supplied paths:

- `agent-bridge/admission-profile-v1.json` — the complete static admission
  descriptor and its canonical digest;
- `agent-bridge/client-declaration-v2.json` — the complete static client
  declaration and its canonical digest.

The profile plan fixes `profile_id`, bridge module contract, bridge module
generation/fence, capability/privacy/effect sets and frame ceiling.
Installation identity, approved Kernel generation/epoch/principal/config
snapshot, staged executable identity/digest and approved SID are its other
inputs. Bridge generation/fence and expected Kernel generation/epoch are
separate authority domains and must never be equated; the Phase-B producer
checks each against its own authoritative source. `profile_id` is derived
deterministically from those immutable inputs; it is not accepted as caller
authority. Host serializes both records,
publishes them with the existing retained-handle Phase-B publication and
rollback discipline, reads both back, reopens the staged executable, and
records a domain-separated pair digest in the durable Phase-B receipt before
constructing `HostKernelCandidateBinding.agent_bridge_admission = Some(...)`.
Kernel accepts only that exact Host-carried descriptor and independently
revalidates the retained declaration and executable bytes against it.

This is one typed optional subplan of `MaterializePhaseB`, not a new ambient
configuration channel or an independently replayable effect. A generation
change replaces the pair only through a new installation transaction; a
connection or interactive-session change does not rewrite it. This decision
authorizes the schema/materialization packet only. Transport admission still
requires the per-connection OS evidence and Kernel challenge/receipt described
below.

The generic `Eliot/kernel/application-client.json` declaration has no
repository writer and is shared by unrelated application clients. It is not an
admission source for this provider. The bridge must use a module-specific,
Host-materialized declaration; the bridge cannot mint generation, fence,
artifact or clock authority locally.

## Current-source blockers

- `bins/eliot-agent-bridge/src/lib.rs` contains the client operation and
  ten-field decoder, while `kernel_ports()` probes and then returns
  `KernelAdmissionRequired` before stdin processing.
- Kernel assembly creates one `ServerHandshakePolicy` for module `eliotd` and
  capability `daemon`; `bind_session` selects no bridge policy.
- The production listener authenticates every connection against one exact
  Host-process `NamedPipePeerExpectation`. Rotating pipe instances reuses the
  same expectation. Because Kernel launches `eliotd` as a distinct process,
  this pre-bind rejects the daemon before the later `validate_eliotd_peer`
  check; it also rejects a distinct agent bridge. The platform/IPC types admit
  one SID/session/process binding rather than a Host-approved sealed peer set.
- Kernel dispatch admits only the current daemon/process routes; it has no
  activation selector.
- the installation package planner contains no bridge artifact or protected
  bridge declaration writer.
- source revision `73f916f` carried an interactive session id and launch nonce
  in the candidate descriptor and sealed only the first process for the whole
  Kernel generation. The version-2 static descriptor/client-template contract
  accepted with this amendment removes those fields. A non-empty production
  profile producer and the Kernel-owned challenge/seal route remain absent.
- `GovernorComposition` retains coordination, session, task, scope and
  observation projections, but `DaemonComposition` exposes no activation
  resolver. Existing validated coordination session/lease helpers are private;
  WorkScope is candidate/ZST-guard state; plan binding is optional evidence.

These blockers make a Kernel-only `Authenticated` response authority
laundering. A handler-only or test-only packet is rejected.

## Ordered implementation packets

### R13.1a — admitted bridge transport

Required effects:

- correct the protected descriptor/client-declaration contracts to static
  generation profiles: no interactive session, connection id or launch nonce
  is candidate-bound;
- materialize and read it through the Host/installation contour with exact
  path/digest evidence and a stable approved user SID;
- add a Kernel-authored per-connection challenge and admission receipt; compare
  the approved SID with a live interactive session and seal PID/start/image/file
  evidence without mutating the candidate or shared handshake policy;
- extend the Windows peer expectation and named-pipe server to a bounded
  sealed peer set containing the Host control client, the exact Kernel-launched
  `eliotd` process receipt, and a bridge admission profile whose valid
  OS-observed PID/start/image/file evidence is sealed for that connection;
  replacements require a fresh challenge/seal, while a caller-supplied PID or a
  synthetic Host-child receipt is never accepted;
- select handshake policy by admitted module identity while preserving the
  existing exact `eliotd` path;
- load a module-specific bridge client declaration.

Exit proof: the exact Host control client and exact Kernel-launched `eliotd`
remain admitted on separate instances, and one real sibling bridge process
completes the authenticated handshake. The same approved user may reconnect in
a new interactive session without a Kernel restart or candidate/permit digest
change. An unapproved sibling, PID reuse or process/start/image/file/SID
substitution, challenge replay, stale generation/fence and descriptor digest
mismatch fail before Session creation.

### R13.1b — reachable activation selector

Required effects:

- move the private activation wire shape into a neutral versioned contract;
- construct the pre-activation identity from protected transport authority;
- add the Kernel selector and typed denial path;
- route the bridge client through it instead of returning locally before the
  stdin loop.

Exit proof: the real admitted process reaches the server selector. With the
resolver absent it receives the exact typed denial. This closes only R13 step
1 and leaves every downstream provider blocker unchanged.

### R13.2 — authoritative semantic binding

Required effects:

- expose one `eliotd` resolver operation over a single captured Governor
  revision;
- make active WorkScope and active-plan authority explicit;
- join principal/session/work item/task revision and reject owner mismatch;
- return a resolver decision bound to the same epoch/fence;
- let Kernel issue the Session/fence and exact ten-field reply.

Exit proof: one real attach returns all ten exact fields, and substitution or
staleness of any field fails closed. Only this packet can close R13 step 2 and
unblock the bridge consumer.

#### Accepted recovery and genesis boundary

Root accepts the recovery boundary on 2026-08-26 against source revision
`a01c6f1b5fbb57a86c7ff80a5ea58e929faab874` and the directive digest recorded
above. This amendment closes an implementation ambiguity; it does not claim a
provider, migration, real attach or Goal completion.

The canonical Store is the durable source for Governor operational owner
state, while `eliotd`/Governor remains the semantic schema owner. Kernel is an
authenticated route and fence/digest verifier only. Kernel must not import
Governor types, decode owner payloads, invent owner records or reconstruct
semantic service readiness from process health.

The Store API therefore exposes one neutral bounded recovery packet containing
opaque schema-bound owner/job records, canonical scope heads and write
receipts. Every record carries the exact `StateFence`, an outer durable
revision, exact canonical payload bytes and their lowercase SHA-256. The
request, every returned record/receipt/scope head and the response must share
one fence. The Host-approved protected snapshot digest remains a Kernel route
binding and is checked before Store access; it is not Store semantic data.
`eliotd`/Governor alone validates the exact 16 owner keys and decodes their
payloads.

First-boot genesis is one atomic, all-absent Store transaction. It writes the
complete opaque owner set plus one replayable seed receipt and advances the
canonical fence sequence without creating active revision/order heads. An
identical operation/idempotency identity returns the exact committed receipt;
the same identity with a different canonical request hash, partial preexisting
state, a stale fence or an unknown unreconciled provider outcome fails closed.
Genesis contains empty task/session/lease state and `current_plan: null`; it
must not fabricate a plan, task, session or WorkScope solely to make startup or
activation tests pass.

Recovery owner state and service observation are separate authorities. After
owner recovery, Governor obtains logical service observations from the actual
service/supervisor owners in startup order. Kernel may return bounded neutral
process/control observations, but it must not return sixteen fabricated
Governor `ServiceObservation::Ready` values. Agent activation requires an
explicit current plan at resolution time and returns the exact typed denial
when it is absent; an empty canonical startup snapshot remains valid.

#### Accepted Authority owner recovery payload

`RecoveryOwner::Authority` is the complete Governor semantic authority state,
not a count projection and not the Kernel's compact ORS enforcement snapshot.
Its canonical opaque payload contains a versioned `GrantGraph` snapshot and a
versioned authorized-effect idempotency ledger. Kernel and Store retain and
fence these bytes but never decode, rebuild or reinterpret them.

The grant snapshot retains the exact graph revision, every complete grant and
parent edge, every authority-set and binding field, issue/expiry time, use
ceiling, status, and the sorted revoked-grant identity set. The authorized-
effect snapshot retains the explicit idempotency key and every field of the
resulting authorized effect: action and operation identity, resource/effect
binding, payload digest, fence, lease identity, executor boundary, and receipt
obligations. Records are deterministically ordered by their durable identity;
duplicates, unknown revocations, missing parents, cycles, widened children,
invalid bindings, substituted idempotency keys, stale fences, malformed
digests, or a zero/substituted graph revision fail closed.

Governor restores this payload through typed constructors and invariant
validation, then installs the already-decided graph and authorized-effect map
without replaying live `revoke` or lease authorization operations. Restoration
must not increment graph revision, reactivate revoked grants, mint a lease, or
fabricate an effect. Active lease state is owned elsewhere and is not inferred
from the authorized-effect ledger. Empty genesis is explicit: graph revision
`1`, no grants, no revoked identities, and no authorized effects.

The Kernel ORS snapshot remains a separate derived enforcement projection.
It cannot replace the Governor semantic payload, and the Governor payload
cannot be accepted merely because an ORS handle or count agrees. A nonempty
round trip must prove exact graph/effect equality after restart; recomputed-
digest semantic substitutions and stale raw-payload digests must both be
rejected.

#### Accepted Surreal recovery-schema migration boundary

R13.2 advances the authoritative Surreal Store schema to generation `2.0.0`
through an explicit additive `1.0.0 -> 2.0.0` migration. The existing v1 DDL,
migration identity and checksum remain immutable historical inputs. A fresh
database may receive an explicitly identified v2 baseline, but that path is not
evidence that an existing v1 database was migrated and must not replace the
forward migration.

The forward migration adds only neutral `recovery_owner` and `recovery_job`
records with unique `(namespace, key)` identity and the Store API's exact
opaque record fields. It must preserve every existing canonical record, head,
receipt, fence, identifier and sequence. `schema_meta.migrations` retains the
v1 entry and appends the checksummed v2 entry; the top-level migration fields
identify that latest entry. No reset, drop, record rewrite, identifier
regeneration or fence rollback is admitted.

Migration remains an explicit installation/Store bootstrap effect. Normal
SystemService startup observes generation `1.0.0` as `MigrationRequired` and
must not apply DDL implicitly or expose the Store pipe as ready. Empty-to-v2,
v1-to-v2 and exact-v2 replay are distinct admitted plans; wrong predecessor,
generation, migration id/checksum, bridge range, config binding, fence or
partial/unknown outcome fails closed. Provider loss after the transaction
boundary remains `UnknownOutcome` until exact migration identity is
reconciled.

Store owns the physical schema and migration receipt. Host may transport the
approved bootstrap binding, and Kernel may verify readiness/generation, but
neither authors Store migration history. Before production cutover, an
isolated v1 rehearsal must prove preservation of existing rows/heads/receipts
and fence, creation of both recovery tables/indexes, restart/exact replay, and
fail-closed partial/unknown outcomes.

Implementation order is contract-first and independently compilable:

1. neutral Store API/wire types and validation;
2. memory and Surreal adapter atomic recovery/genesis parity;
3. Kernel-service Store client plus authenticated Kernel route;
4. Governor opaque-record decode, empty genesis builder and service-observation
   split;
5. `eliotd` compound recovery call and real startup/readiness sequencing;
6. first-boot, restart, replay, partial-seed, stale-fence,
   protected-digest, unknown-outcome and no-active-plan integration proofs.

Adding only Kernel operation strings or mapping Governor owner names to
invented Store keys is explicitly rejected: no authoritative persisted
key/schema mapping or atomic recovery bundle exists until the preceding Store
contract and provider waves land.

## Mandatory negative matrix

- descriptor missing, malformed, digest-mismatched or outside the approved
  installation generation;
- foreign SID/session/PID/start/image/file/Job, replayed connection challenge,
  stale generation,
  authority epoch or state fence;
- unknown capability/privacy/effect or wrong client module;
- missing/reused pre-activation identity, or a client-supplied semantic
  principal/session/task/WorkScope/plan;
- same request/idempotency key with changed payload;
- inactive/revoked/expired semantic session or lease;
- principal/session disagreement between coordination and lifecycle owners;
- missing/ambiguous/stale WorkScope, task/work-item mismatch, zero/stale task
  revision, missing/stale active plan;
- resolver decision fence differing from the admitted transport fence;
- replay after Kernel/eliotd restart or generation change;
- logoff/session rotation revokes the old connection seal while leaving the
  Kernel candidate and activation permit digest unchanged;
- missing, extra or substituted field in the ten-field `Authenticated` reply;
- resolver unavailable: exact typed `Denied`, never local success and never a
  fabricated partial binding.

## Dependency and proof boundaries

- Kernel must not depend on `eliot-cli`, `eliot-agent-bridge-core` or the
  `eliotd` binary crate.
- Surface crates must not own the Host/Kernel admission descriptor.
- `IntegrationDiscoveryCatalogue` remains discovery-only.
- Existing `Session::establish_with_server` remains the exact handshake
  verifier after Kernel selects the admitted module policy; this decision does
  not weaken it.
- No consumer after R13 step 1 is authorized before its provider.
- No hosted execution, ProgramData mutation, service installation, schema
  migration, consumer unblock or Goal completion is claimed by this decision.

## Review and rollback

Review this decision after R13.2 produces one real attach receipt, or earlier
if an implementation would add a second semantic owner, weaken exact peer
evidence, or require the bridge to self-assert authority.

Rollback is packet-local: remove the new descriptor/profile/operation route,
restore the existing closed bridge refusal, preserve the exact rejection
evidence, and leave existing `eliotd`, process and store contours unchanged.
No persisted semantic state is deleted or rewritten.
