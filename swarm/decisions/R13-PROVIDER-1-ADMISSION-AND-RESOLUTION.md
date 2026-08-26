# R13 provider #1 — admission and semantic-resolution boundary

Status: `ACCEPTED_SOL_BOUNDARY`

Implementation state: `BLOCKED_AS_SINGLE_CELL`

Authority: Root / Sol under `ROOT-DIRECTIVE-v1.5.md` §2, §7 and §9,
Recovery Program §5.1 rule R13, and normative Implementation “Session attach”.
Accepted on 2026-08-26 against:

- source revision `f39d9cfbc084444775ce4802462fbe5b9a0e7ff6`;
- `ROOT-DIRECTIVE-v1.5.md` SHA-256
  `C12C3B15229286B887483BAE4B2B1CD8023F243897E84F77855D891EBE1E7BB4`.

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

1. **Transport admission.** Host/installation owns a protected, versioned
   `AgentBridgeAdmissionDescriptor`. Kernel consumes it and selects a
   bridge-specific handshake/peer policy. The existing `eliotd` policy remains
   exact and unchanged.
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
| Bridge admission declaration | Host/installation | Protected descriptor bound to the approved installation/generation and exact observed process/image evidence |
| Pipe ACL and peer authentication | Kernel IPC + Windows platform adapter | Host-approved sealed peer set and OS-observed SID/session/PID/start/image/Job evidence for each admitted process |
| Activation request/reply wire | `eliot-protocol` | Closed, versioned request, `Authenticated` and `Denied` records shared without a Kernel→surface dependency |
| Semantic principal/session | `eliotd` resolver over Governor owners | Active `CoordinationOwner::AgentSession`, cross-checked with `SessionLifecycleOwner` epoch/fence/lifecycle |
| Task/work unit | `eliotd` resolver over Governor owners | Active coordination work item/lease joined to the canonical `TaskLifecycleOwner::TaskRecord` revision |
| WorkScope | `eliotd` resolver | A current `MATCHED` ScopeBindingGuard receipt; a candidate or the current ZST guard alone is not authority |
| Plan | `eliotd` resolver | One current active-plan binding for the selected task/scope; optional observation evidence alone is not authority |
| Transport Session and bridge fence | Kernel | Admitted peer + resolver decision + matching authority epoch/resource generation/state fence |

The resolver is an authority **boundary**, not a new state owner. Until the
missing WorkScope receipt owner and current active-plan read path exist,
`Authenticated` remains forbidden and the resolver must return a typed denial.

Host/installation owns the protected admission policy and allowed peer
profiles. Kernel owns the live OS peer observation and the current operational
generation/epoch/fence comparison. A descriptor is an immutable admitted input;
it never replaces Kernel's live evidence or becomes a mutable-current-fence
oracle. `ClientHello` remains a claim checked against both sources.

## Admission descriptor contract

The descriptor is separate from the discovery catalogue and from the fixed
Phase-A runtime-child manifest. Discovery proves presence only. Adding the
external bridge to `REQUIRED_PACKAGE_ROLES` or `RuntimeLaunchDescriptor` would
change the installed-child schema and requires a separate migration decision;
this decision does not authorize that shortcut.

The protected descriptor must bind at least:

- descriptor wire id/version and canonical digest;
- module id `eliot-agent-bridge` and exact executable path/SHA-256;
- approved resource generation, authority epoch and state fence;
- Host-issued launch nonce or exact Host process/Job receipt;
- approved caller SID/session plus process/image policy;
- allowed capability, privacy and effect sets;
- expected Kernel principal/config snapshot digest;
- immutable inputs for the module-specific protected client declaration used
  to form `ClientHello`.

The descriptor must not store a reusable `RequestIdentity`, semantic
principal, Session, task, WorkScope, plan, mutable clock, or mutable current
fence. The bridge derives a fresh pre-activation identity per request from the
authenticated transport snapshot and server-provided bounded clock. Its semantic
session/task fields remain `None`; the activation payload carries correlation
and attach intent, not caller-selected semantic identities.

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
- `GovernorComposition` retains coordination, session, task, scope and
  observation projections, but `DaemonComposition` exposes no activation
  resolver. Existing validated coordination session/lease helpers are private;
  WorkScope is candidate/ZST-guard state; plan binding is optional evidence.

These blockers make a Kernel-only `Authenticated` response authority
laundering. A handler-only or test-only packet is rejected.

## Ordered implementation packets

### R13.1a — admitted bridge transport

Required effects:

- add the protected descriptor contract to the existing Host↔Kernel carrier
  `eliot-kernel-service::protocol`;
- materialize and read it through the Host/installation contour with exact
  path/digest/process evidence;
- extend the Windows peer expectation and named-pipe server to a bounded
  sealed peer set containing the Host control client, the exact Kernel-launched
  `eliotd` process receipt, and a bridge admission profile whose first valid
  OS-observed PID/start/image is sealed for that generation; a caller-supplied
  PID or a synthetic Host-child receipt is never accepted;
- select handshake policy by admitted module identity while preserving the
  existing exact `eliotd` path;
- load a module-specific bridge client declaration.

Exit proof: the exact Host control client and exact Kernel-launched `eliotd`
remain admitted on separate instances, and one real sibling bridge process
completes the authenticated handshake. An unapproved sibling, PID reuse or
process/start/image/SID substitution, stale generation/fence and descriptor
digest mismatch fail before Session creation.

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

## Mandatory negative matrix

- descriptor missing, malformed, digest-mismatched or outside the approved
  installation generation;
- foreign SID/session/PID/start/image/Job, stale launch nonce, generation,
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
