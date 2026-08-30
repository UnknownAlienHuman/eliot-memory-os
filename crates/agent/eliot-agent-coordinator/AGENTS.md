# Agent Coordinator source instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_router.py route --path <repository/path> --topic "<causal property>"
```

Read every fragment marked **required**, then record the emitted receipt in the
work unit or pull request. Optional fragments are loaded only when the current
decision crosses their stated boundary. A legacy `ELIOT_*` compatibility map is
never an acceptable reading receipt.

If no non-baseline route matches, stop the mutation and add or obtain a route;
silence is not permission. See [`../../../docs/architecture/READING_PROTOCOL.md`](../../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->


## Purpose and authority

This package is the existing Rust A-02 owner for deterministic candidate
staffing, route selection, externally admitted attempt reconciliation and
bounded peer delivery. It owns no provider process, model execution, current
account catalogue, credentials, task truth, global policy, canonical writer or
task finish.

The public contract owner for route identity is
`eliot-agent-api::RouteFingerprint`. This package consumes that field-complete
value and produces candidate-only `RoutingReceipt` values inside a
`StaffingPlanCandidate`.

Issue #224 owns current route-selection migration and hardening. Issue #187
remains the product/integration objective. Read both issues, repository
instructions and the applicable Architecture/Implementation fragments before
mutation.

## Functional capability cells

Several cells share this package because they use one plan/attempt contract
island and one package proof boundary. They do not acquire each other's
external authority.

### `agent.coordinator.staffing-plan`

Owned entrypoint:

```rust
AgentCoordinator::plan(StaffingPlanRequest)
    -> Result<StaffingPlanCandidate, CoordinatorError>
```

Responsibility:

- validate one task/plan/State-Fence-bound launch request;
- validate recipe, roles, work units, budgets and mutation scopes;
- compile deterministic candidate lanes;
- preserve backpressure and one-writer scope constraints;
- emit a candidate only; no process is launched or admitted.

### `agent.coordinator.route-selection`

Owned private entrypoint:

```rust
select_route(
    &CoordinatorConfig,
    &StaffingPlanRequest,
    &RoleProfileManifest,
    Vec<RouteCandidateEvidence>,
) -> Result<RoutingReceipt, CoordinatorError>
```

Responsibility:

- consume field-complete `RouteFingerprint` values from `eliot-agent-api`;
- consume immutable route/capacity/budget/capability evidence or exact owner
  references;
- reject stale, unknown, unreceipted or incompatible required dimensions;
- select deterministically under the current recipe/policy revision;
- preserve rejected alternatives, reason codes and evidence handles;
- return `ProofCeiling::CandidateArtifact` only.

Selection cannot dispatch, reserve a provider, mint a WorkLease, prove current
availability, satisfy an EvaluationContract or establish independent
verification.

### `agent.coordinator.provider-admission`

Owned entrypoint:

```rust
AgentCoordinator::admit(ProviderAdmissionReceipt)
```

Responsibility:

- recheck exact candidate, task/plan/fence, route, budget and lane identity;
- require the sealed provider verifier for accepted A-01/G-11 evidence;
- preserve idempotency and reject stale provider/capacity generations;
- create no provider authority locally.

The public constructor intentionally installs a typed `PLAN_GAP` provider until
an accepted adapter exists. Do not add a caller-implementable or
`always_verified` verifier.

### `agent.coordinator.attempt-reconciliation`

Owns bounded attempt start, cancellation, worker-loss fencing, reassignment,
result submission, unknown-outcome reconciliation and descendant closure. An
attempt result is a candidate artifact and never a Task finish decision.

### `agent.coordinator.peer-delivery`

Owns read-only coordination-map projection and explicit queued/delivered peer
message state. It is not a group-chat control plane and does not create shared
mutable task intent.

## Current Python prototype disposition

`scripts/agent_model_selector.py` and
`integrations/agent-runtimes/model-selection.*.json` are a
`development_only / differential_oracle` prototype under #224.

They are not:

```text
the RouteFingerprint owner;
the current-account Capability Registry;
the route policy owner;
a durable RoutingReceipt producer;
a provider admission surface;
a production control-plane implementation.
```

Until the prototype is migrated:

- no production Rust/daemon/bridge surface may import or execute it as routing
  authority;
- its output must remain candidate/oracle evidence and cannot be admitted by
  filename or schema name;
- placeholder fixture identities are synthetic;
- a Python selection cannot be called a current route, provider acceptance,
  capability proof or AgentAttempt result;
- retained deterministic behavior must move into this package or its existing
  public contract owner, then be differential-tested before the prototype is
  removed.

Do not create a second route-selection crate merely because the prototype has a
separate file. The current owner, consumer and proof boundary already exist.

## Route identity and evidence

Use `eliot-agent-api::RouteFingerprint` exactly once. It includes all
behavior-bearing fields:

```text
host family;
adapter;
protocol/transport;
runtime and adapter hashes;
provider and model;
auth/billing mode;
serializer and tool-semantics hashes;
reasoning mode;
continuation behavior;
feature flags.
```

Do not collapse this value to a vendor/model tuple or a caller-provided digest
string. A change to any behavior-bearing field creates a different route
fingerprint and invalidates dependent capability/outcome evidence.

Route selection must keep these dimensions orthogonal:

```text
catalogue identity/currentness;
route admission;
liveness/readiness/capacity;
availability;
quota knowledge;
budget/cost;
capability support and its evidence source;
evidence execution/currentness;
privacy/execution identity;
independence profile;
route outcome profile;
Task/plan/State Fence.
```

A caller string such as `current`, `admitted`, `healthy`, `available`,
`supported` or `verified` creates no state. Every load-bearing dimension needs
an exact accepted value or owner receipt/reference.

Unknown quota or availability is not encoded as zero or success. Missing
capability evidence is unsupported. Source/document presence does not prove
behavior. A different model name does not prove a different failure domain.

## Policy and diversity

The System Owner/Requester policy supplies allowable route classes, privacy and
cost ceilings. Task Controller may narrow them. This package applies the exact
policy/recipe revision; it cannot invent or expand it.

No fixed universal model ID, ambient alias, static vendor ratio or permanent
host enum is permitted. Host/provider families come from the extensible current
catalogue and accepted capability evidence.

Diversity is not a vote and not one score. A requirement may distinguish:

```text
host and adapter;
provider/account/billing route;
model family;
evidence lineage;
evaluator;
observation route;
implementation/toolchain;
failure domain;
conceptual frame.
```

A different host/model with shared evidence is still dependent on that evidence.
`degraded diversity` is valid candidate metadata but cannot satisfy an explicit
independent-verifier requirement. Verifier staffing also requires the
applicable EvaluationContract; `code_review + reasoning` alone is insufficient.

## Ranking and determinism

Selection is deterministic for equivalent admitted inputs, but determinism does
not validate the inputs.

Required ranking behavior:

1. reject every candidate that fails a required eligibility dimension;
2. apply exact role/policy/budget/context/capacity requirements;
3. apply declared independence/diversity constraints;
4. rank only the remaining candidates using a versioned policy;
5. use stable field-complete route identity as final tie-break;
6. preserve all material rejection reasons and evidence handles;
7. never silently fall back after meaningful provider output or an external
   effect.

Scalar preference rank may remain a policy input only when every eligibility
and evidence dimension was validated first. It cannot replace capability,
currentness, quota, privacy or independence checks.

## Candidate and admission boundary

```text
Capability Registry / Policy / Capacity evidence
→ StaffingPlanRequest
→ deterministic StaffingPlanCandidate + RoutingReceipt
→ external provider/Governor admission
→ ProviderAdmissionReceipt
→ exact Attempt lifecycle.
```

The first arrow is not owned by this package. The candidate receipt has no
dispatch authority. Provider/Governor admission must bind the exact candidate
bytes/digest and cannot reinterpret a newer policy or route under the same
identity.

`ActualRouteReceipt` remains distinct from requested routing. Unknown actual
provider/model/billing identity cannot satisfy independence, provider-specific
privacy, billing or route-specific verification claims.

No silent mid-attempt failover is allowed. Before provider work begins, a new
route may be selected under policy. After meaningful output/tool/effect, a
substitution creates a new Attempt with a sealed causal handoff.

## Immutable candidate identity and publication

A routing/staffing candidate is immutable for its identity. Replaying exact
canonical bytes returns the same candidate. Reusing identity with changed bytes
is a conflict.

Development files named `receipt` do not gain receipt authority. Any retained
prototype output written to disk must use create-new/idempotent-readback and an
atomic publication path, or stdout only. Overwriting an existing candidate is
forbidden.

## Hard boundaries

Do not add:

- provider/model SDKs or process launch to the pure coordinator core;
- credentials, API keys, tokens or user-session secret material;
- a parallel RouteFingerprint, RuntimeRoute, capability registry, route policy
  or receipt schema;
- caller-provided readiness/currentness as trusted state;
- model-name capability inference;
- a fixed closed host/vendor enum;
- an ordinal evidence score that collapses execution, currentness, support and
  independence;
- provider admission without the sealed verifier;
- task truth, acceptance, authority, WorkLease minting, external effects or
  finish ownership;
- a generic shell or raw provider command;
- unbounded candidate/role/rejection collections;
- automatic GitHub Actions.

Return a ContractChallenge when work needs:

- a current-account catalogue contract that has no accepted owner;
- new field-level CapabilityEvidence/IndependenceProfile semantics;
- provider execution or user-broker credentials;
- policy expansion;
- a new receipt lifecycle;
- evidence unavailable inside the granted source/edge unit.

## Required source units

### Prototype-hardening unit

May change only:

```text
scripts/agent_model_selector.py;
scripts/select-agent-models.py;
integrations/agent-runtimes/model-selection.policy.json;
integrations/agent-runtimes/model-selection.fixture.json;
focused prototype tests/docs.
```

It may close malformed-input, mutable-output and development-only labeling bugs.
It cannot claim Rust/current-account integration.

### Contract/Evidence unit

Owns exact current-account catalogue/capability/policy input types in the
existing public contract owner. Do not define them privately in `core.rs` or
Python.

### Coordinator Module-cell unit

Changes route eligibility/ranking inside this package and focused tests only.
It does not also change provider adapters, policy or Capability Registry.

### Edge unit

Wires real Capability Registry/Policy/Capacity evidence to
`StaffingPlanCandidate` and the sealed provider admission path.

## Proof

Minimum package proof for Rust changes:

```text
cargo fmt --all -- --check
cargo check --locked -p eliot-agent-api --all-targets
cargo test --locked -p eliot-agent-api
cargo check --locked -p eliot-agent-coordinator --all-targets
cargo test --locked -p eliot-agent-coordinator
cargo clippy --locked -p eliot-agent-api -p eliot-agent-coordinator --all-targets -- -D warnings
```

Required route-selection package fixtures:

```text
field-complete RouteFingerprint round-trip;
changed serializer/tool/adapter/runtime fingerprint invalidates evidence;
caller self-report cannot mint current/admitted/healthy/available;
unknown quota is not dispatchable;
missing capability evidence is unsupported;
Task/plan/fence/privacy/budget/policy/capacity mismatch;
permutation determinism;
no model-name inference or universal model ID;
independence/degraded-diversity behavior;
exact replay and changed-byte conflict;
no provider execution or dispatch before admission.
```

Prototype hardening requires its own direct Python self-test and malformed-CLI
cases, but that proof ceiling remains development-oracle only.

Real Edge Proof requires:

```text
current-account Capability Registry and policy input;
one exact admitted route per supported host;
provider admission and ActualRouteReceipt;
quota/route-drift/cancellation/tool-outcome negatives;
no silent failover;
current Product Identity and State Fence.
```

Package proof does not establish current account, live provider acceptance,
route availability, tool behavior, cancellation, attempt completion or Product
success. Report all unexecuted edges exactly.
