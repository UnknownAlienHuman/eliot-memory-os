# Agent API contract source instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Repeat `--path` for every mutable path family, or use `--changed-from
origin/main` for the complete branch delta, including deletions. Open the
verified bundle and read every required item before mutation. A route alone is
navigation, not reading evidence.

Record the route receipt ID, read receipt ID, matched routes, required handles,
fragment paths and SHA-256 values, verified bundle SHA-256, and explicit reading
attestation in the work unit or pull request. Optional fragments are loaded only
when the current decision crosses their stated boundary. A legacy `ELIOT_*`
compatibility map is never an acceptable read receipt.

If no non-baseline route matches, a required item is stale or missing, or scope
expands beyond the receipt, stop and rerun or repair the route; silence is not
permission. See [`../../../docs/architecture/READING_PROTOCOL.md`](../../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->

## Purpose and current status

This package is a provider-neutral C0 contract boundary for agent admission,
attempts, route identity, host observations, effect candidates and worker result
candidates. It owns no mutable state, provider process, route policy, capability
registry, task plan, authority decision, canonical write or task finish.

Issue #228 records confirmed contract collisions in the current source. Until its
Contract/Evidence wave freezes the field-level owners and compatibility plan,
do not perform a broad source rewrite or let a local type become a convenient
second owner.

Read the repository instructions, #228, related route work #224/#187, strict
finish owner #18, and the applicable Architecture/Implementation fragments
before mutation.

## Functional capability cells

### `agent.contracts.route-fingerprint`

Owns the provider-neutral, field-complete identity of one behaviorally distinct
route. It describes identity only; it does not say that a route is installed,
current, healthy, admitted, available, affordable or authorized.

A route fingerprint changes when any behavior-bearing component changes:

```text
host family;
adapter;
protocol and transport;
runtime artifact;
adapter artifact;
provider/model/auth/billing route;
serializer/chat template;
tool semantics;
reasoning mode;
continuation behavior;
feature flags.
```

Every field named as a hash/digest must use the accepted shared digest primitive
or exact algorithm-qualified validation. Nonblank placeholders such as
`sha256:runtime` are invalid production identities.

### `agent.contracts.attempt`

Owns provider-neutral shapes for an admitted/executing agent attempt and its
bounded state transitions. It consumes shared task, WorkScope, lease, epoch,
State Fence, budget and effect-ceiling contracts. It does not mint those values
or define task completion.

### `agent.contracts.host-event`

Owns normalized host/provider event envelopes and continuity observations. Raw
provider payload remains behind an immutable raw/redacted handle. Policy,
authority, task, finish and current capability logic may consume only typed,
versioned ELIOT-owned normalized payloads.

### `agent.contracts.effect-candidate`

Owns candidate effect description and exact linkage to an externally supplied
authority/effect ceiling. A valid proposal is not an AuthorizedEffect and an
effect receipt is not task proof.

### `agent.contracts.result-candidate`

Owns a worker/provider candidate result and explicit attempt-level outcome. It
is structurally incapable of declaring Task `VERIFIED_COMPLETE`; the Governor
Finish service alone derives the task finish decision from current contracts,
artifacts, executed verifier evidence, State Fence and reconciled effects.

## Current ContractChallenges

### Duplicate shared identities

Current source locally declares opaque strings named:

```text
TaskId;
ArtifactId;
AuthorityEpoch;
SessionId;
WorkLeaseId;
AttemptId;
WorkUnitId;
...
```

Several names already have shared ELIOT owners. Do not extend these wrappers or
add another conversion facade. The #228 inventory must classify each local type:

```text
reuse exact shared identity;
introduce one missing identity in the correct foundation contract;
retain as truly agent-local with explicit namespace;
remove as duplicate.
```

At minimum, task, artifact, Authority Epoch, WorkScope/State Fence and common
receipt/effect identities must not remain unrelated strings.

### Weak Authority Epoch and State Fence

`AuthorityEpoch(String)` and `state_fence: String` cannot express epoch lineage,
sequence, restore fencing or exact dependency revisions. No new contract may
use these fields as proof of current authority. Migrate through the accepted
shared typed contracts; do not parse meaning from display strings.

### Multiple route-choice representations

Current source contains `CapabilityRouteDecision` and a public
`eliot_agent_api::RoutingReceipt`. `eliot-agent-coordinator` contains a second,
incompatible `RoutingReceipt` used by staffing-plan selection.

Until #228 freezes exact meanings and owners:

```text
do not add fields independently to either RoutingReceipt;
do not expose either one as the universal route decision;
do not add a third route selection result;
do not convert between them by lossy string mapping;
do not let Python oracle output satisfy either contract.
```

The contract wave must distinguish and name exactly:

```text
RouteFingerprint                  identity only;
RouteSelectionCandidate/Decision  candidate-only deterministic choice;
RoutingReceipt                    admitted durable logical route decision, if needed;
ActualRouteReceipt                observed physical route/usage evidence.
```

Every field-level type has one owner and one compatibility path.

### Worker-controlled `VerifiedComplete`

Current `AgentResult` accepts `ResultDisposition::VerifiedComplete` and checks
only that `evidence_refs` is nonempty. This is not an admissible finish
boundary.

Do not add code, tests or consumers that treat this variant as task completion.
Do not add a conversion from `AgentResult`, provider `completed`, process exit,
nonempty evidence handles or model prose to `FinishDecision::VERIFIED_COMPLETE`.

The migration must introduce or reuse an attempt/result disposition whose
strongest positive state means only a candidate result succeeded at its own
proof ceiling. The Finish service separately derives task finish. Add a compile
or negative fixture proving the worker/provider schema cannot express task
completion.

### Requested versus observed route mismatch

Current `ActualRouteReceipt` and `PhysicalModelAttemptReceipt` return a contract
error whenever observed route differs from requested route. A mismatch is
material evidence, not evidence that no attempt occurred.

The corrected contract must preserve both fingerprints and expose a typed
mismatch/degradation disposition that caps proof and triggers the appropriate
reconciliation/quarantine owner. It must never silently substitute the route or
discard the physical-attempt evidence.

### Weak digests and timestamps

Current tests use non-digests such as:

```text
sha256:runtime;
sha256:adapter;
sha256:serializer;
sha256:tools;
sha256:features.
```

Fields named `*_hash`, `*_digest`, request/payload/raw hashes and exact artifact
identity must use shared digest contracts or exact validators. Time fields used
for expiry, attempt timing or evidence freshness require a shared typed clock or
an exact timezone-bearing compatibility contract. A nonblank string is not
proof.

### Generic normalized payload

`HostEventEnvelope.normalized_payload: serde_json::Value` is not a closed
policy/control contract. Do not add policy, authority, completion or capability
logic that interprets arbitrary keys inside it.

The contract wave must provide typed event payload families or one bounded
versioned extension envelope with:

```text
payload kind/schema identity;
raw/redacted source handle and digest;
normalizer/adapter version;
loss and warning manifest;
unknown-version behavior;
privacy/disclosure metadata;
proof ceiling.
```

## Contract ownership rules

1. Reuse shared C0 primitives rather than reimplementing IDs, epochs, fences,
   time, digest, receipts or effects locally.
2. Public contracts contain no provider SDK, transport implementation, process
   handle, credential value or vendor database type.
3. A route name, model name or provider label never proves capability,
   readiness, independence, quota or currentness.
4. Requested route, selected logical route, observed physical route and current
   Capability Registry status remain different objects.
5. A candidate or model result gains no authority or factual support by its
   schema, role or confident format.
6. Unknown outcome, route mismatch, truncated payload and missing observability
   remain explicit and preserve evidence.
7. Common receipt fields are owned once by the canonical ReceiptEnvelope or an
   accepted shared receipt contract; local typed payloads do not redefine them.
8. Every collection and payload has explicit bounds and omission/expansion
   behavior.
9. Compatibility is versioned and loss-visible; old serialized shapes are not
   silently reinterpreted as stronger contracts.
10. The package remains stateless and effect-free.

## Required work decomposition

Do not assign #228 as one broad implementation unit.

### Contract inventory unit

Produces a machine-readable or reviewed map of:

```text
public type/field;
current owner;
duplicate definitions;
producers/consumers;
serialized compatibility;
retain/merge/rename/remove disposition;
first affected proof.
```

No source schema changes in this unit.

### Foundation identity units

Add or harden shared identity/digest/time/fence primitives only where the
existing foundation owner lacks the required contract. One primitive family per
causal unit.

### Agent API contract unit

After the inventory and shared primitives freeze, change exact route, event,
effect and result candidate shapes with package compatibility fixtures.

### Coordinator consumer unit

Migrate staffing route selection and provider admission to the accepted shared
contract. It does not also change provider adapters or Finish service.

### Provider/bridge consumer units

Migrate raw/normalized events, actual-route evidence, usage and cancellation one
adapter family at a time.

### Finish edge unit

Prove candidate result -> current strict Finish service and finish-forgery
negative behavior. No agent contract owns finish.

### Product Pulse

Run one real route/attempt including route drift, cancellation, verifier,
unknown outcome and attempted completion forgery.

## Required negative fixtures

Package/contract proof must include:

```text
local string epoch cannot satisfy shared EpochId;
wrong State Fence dependency is rejected;
malformed behavior-bearing digest fails;
unzoned/invalid required time fails;
changed serializer/tool/runtime/feature identity changes RouteFingerprint;
only one RoutingReceipt owner/import path remains;
old route-choice schemas have explicit migration dispositions;
requested/observed mismatch remains evidence with a reduced ceiling;
unknown event payload cannot drive policy/authority/finish;
AgentResult cannot encode or convert to task VERIFIED_COMPLETE;
nonempty arbitrary evidence refs cannot satisfy finish;
unknown outcome requires reconciliation evidence;
every changed real producer/consumer compiles against the single owner.
```

## Hard boundaries

Do not add:

- provider/model SDKs, process launch or credentials;
- canonical store, ORS, task, policy, Capability Registry or finish ownership;
- another local TaskId/ArtifactId/Epoch/StateFence/Receipt definition;
- another route selection receipt or universal status enum;
- generic JSON as a substitute for a missing typed policy contract;
- string parsing as the permanent shared-identity boundary;
- model-name inference, automatic provider fallback or route self-certification;
- `VerifiedComplete` to any worker/provider-controlled result;
- unbounded payloads or collections;
- automatic GitHub Actions.

Return a ContractChallenge when the work requires a public field whose owner is
unresolved, a cross-package compatibility wave not granted to the work unit, a
provider/effect/finish decision, or runtime evidence unavailable to the package.

## Proof

Minimum package proof after a source change:

```text
cargo fmt --all -- --check
cargo check --locked -p eliot-agent-api --all-targets
cargo test --locked -p eliot-agent-api
cargo clippy --locked -p eliot-agent-api --all-targets -- -D warnings
```

A public contract change also requires:

```text
schema/serialization compatibility fixtures;
all direct/reverse Rust consumers;
coordinator contract fixtures;
first affected provider/bridge fixture;
finish-forgery fixture when result semantics change;
exact current-main identity and changed-path evidence.
```

Package proof establishes contract behavior only. It does not prove current
Capability Registry state, provider execution, host-event completeness, route
admission, cancellation, external effects, strict task finish, Product Pulse or
release support. Report each unavailable edge as `NOT_EXECUTED`; do not enable
automatic CI to manufacture a status.
