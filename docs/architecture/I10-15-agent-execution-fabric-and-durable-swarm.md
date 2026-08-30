## I10.15. Agent Execution Fabric and durable swarm

Agent Execution Fabric extends the existing Host Broker and Agent Coordinator. It does not introduce a second scheduler, task store, attempt journal, write authority or recovery path.

A model-produced plan is never executed directly. It is compiled through a deterministic `TaskGraphCompiler`:

```text
Planner Candidate
→ schema and objective/acceptance linkage
→ dependency and ownership validation
→ effect/authority and WorkScope validation
→ cycle check; bounded loop compilation with max iterations/budget/termination
→ overlap, WIP, environment and budget analysis
→ immutable SwarmPlanDefinition
→ Governor admission
→ Ready Queue execution.
```

The durable execution unit is an `AgentAttempt`, not an agent personality. A route/session is an ephemeral executor attached to one attempt with exact packet, budget, lease, artifact lineage and continuity kind. Free-form group chat may be captured as a research artifact, but it is not the task graph, mailbox or completion mechanism.

Agent output is typed:

```text
artifacts;
evidence;
findings and rivals;
proposed effects;
unresolved questions;
proposed next work.
```

A proposed effect follows proposal → authorization → idempotent execution → effect receipt. A worker, component or synthesis agent cannot perform the commit merely because it generated the proposal.

```text
Human / Main Agent
→ ExecutionIntent: goal-linked role, assurance, cost and privacy preference
→ Recipe Planner chooses the simplest admissible workflow
→ Route Allocator selects evidence-backed runtime routes
→ Ready Queue runs a fenced admission saga for internal WIP, cost/quota budget and resource claims
→ adapters execute bounded attempts
→ Governor reconciles events, artifacts, evidence and verification
→ the named content/acceptance decision owner resolves substantive ambiguity.
```

The system unifies task/lifecycle/evidence, not vendor internals.

`RecipePlanner`, `RouteAllocator` and Ready Queue admission are deterministic/policy capabilities of `AgentCoordinator` inside `eliotd`. Main Agent, Dreamer or a planning worker may propose decomposition, recipe or route preferences, but the proposal remains a Candidate until dependency, impact, capability, budget, privacy and overlap checks pass. None of these capabilities owns a second task graph or substantive decision authority.

### Semantic objects

```text
SwarmPlanDefinition
  immutable orchestration proposal bound to one task/recipe revision: objective, acceptance links,
  Task Controller lease/epoch, RootContextRevision, work graph, privacy/budget/route/depth/fanout/WIP
  ceilings and stop conditions; each definition revision is authored only by the Task Controller;

SwarmPlanAdmission
  Governor-owned disposition of one exact SwarmPlanDefinition under a Policy/Capability/State Fence:
  admitted, rejected, stale, cancelled or superseded; it records admissible ceilings and a receipt
  but cannot rewrite the definition or substantive task choice;

SwarmExecutionState
  execution/aggregation revision for one admitted definition: coordinator lease/epoch,
  current wave, assignment/checkpoint/reduction state, coverage ledger and operational outcome;
  owned by AgentCoordinator under the SwarmCoordinatorLease and unable to widen the admitted plan;

RoleProfileId and RecipeId
  opaque, versioned manifest IDs; no closed vendor enum;

RootContextRevision / SwarmWave
  immutable shared root handles, State Fence and disclosure policy for one execution wave;
  a changed root creates a new wave and forces descendant revalidation rather than silent context mutation;

CoordinationMapView
  rebuildable recipient-addressing projection over one frozen SwarmPlanDefinition and current execution
  assignments: work-item identity, one-line responsibility, dependency/overlap edges, assigned attempt/role
  and mailbox route handle; it contains no mutable plan state and creates no semantic subscription owner;

ReductionPlan
  bounded fan-in tree, deterministic pre-dedup/grouping, lineage preservation,
  synthesis stages and stop/escalation rules;

RoleProfileManifest
  semantic role, allowed operations/effects, required competence and independence,
  input/output contract, stop/escalation and visibility limits;
  learning_role: actor | refiner | evaluator | promotion_owner | not_applicable;

RecipeManifest
  ordered/parallel stages, work-item templates, dependency/merge rules,
  admissible role/route classes, expansion/contraction conditions,
  verifier/audit requirements, budget and failure/partial-result behavior;

ExecutionIntent
  role, assurance, budget class, route-class preference,
  independence requirement and optional recipe hint;

ParallelismEvidence
  decomposition/path claims, shared invariants, overlap,
  merge cost, environment contention and expected information gain;

StaffingPlan
  recipe revision, lanes, expansion/contraction rules,
  admission, audit and resource-mix policy;

RoutingReceipt
  requested class, selected RouteFingerprint, rejected alternatives,
  current capability/quota evidence and cost/privacy rationale.
```

Definition, admission and execution lifecycles are separate and are defined once in I14.20. At this layer ownership is fixed: Task Controller owns `SwarmPlanDefinition` revisions; Governor owns `SwarmPlanAdmission`; AgentCoordinator owns `SwarmExecutionState` under an exact active admission.

The SurrealDB DEFAULT uses separate definition, admission and execution records with separate owner revisions/Ordering Scopes. Another store may co-locate them physically only if field ownership, revisions and immutable owner events remain enforceable. A derived `SwarmPlanView` may join them for reads, but is not a mutable owner. AgentCoordinator may advance execution mechanically only under an active admission receipt; any change to objective, acceptance, ceilings, work graph semantics or stop conditions requires a new Task Controller definition revision and a new Governor admission. A new definition never mutates a running wave in place: the Task Controller proposes drain/cancel/supersession, Governor admits the disposition, and a new execution revision starts against the new definition. None of these objects owns task truth: task finish remains I7.9. Loss of Task Controller or coordinator revokes only the corresponding lease; definitions, admission receipts, work items, events, evidence and verified partial results survive and are reassigned under a newer epoch.

Recipe/role manifests are content-addressed, versioned and policy-approved inputs compiled into existing `AgentInvocationRequest`, `HostLaunchContract`, Durable Jobs, leases and receipts. Distributed/external bundles additionally require signature verification; local built-ins do not gain a pointless signing ceremony. Unknown manifests are not executable until schema, provenance and policy validation.


### Module-oriented development swarms

For software implementation, decomposition starts from `BuildTestGraph` and the generated `EffectiveMicroModuleManifest`, not from arbitrary file count.

```text
contract/fixture lane
→ independent module implementation lanes
→ module-local InstrumentProfile proofs
→ affected edge integration lane
→ blind causal/property audit
→ one governed IntegrationLease.
```

Each work item names one primary micro-module, frozen public contract revision, exact discriminator, independent test command and affected integration edges. Agents may inspect wider context but cannot widen their write scope silently. Cross-cutting contract or schema changes are planned as their own ordered wave before consumer implementations.

Parallelism is rejected when agents would edit the same mutable owner, share an unisolated build/runtime resource, require the same sequential reasoning state or create merge cost larger than expected evidence value.

### Built-in recipes

First supported recipes:

```text
SoloVerified
  one capable agent → deterministic verifier → optional narrow review;

ScoutThenImplement
  read-only scout → compact evidence/plan artifact → fresh single writer → verifier;

ParallelEvidenceSynthesis
  bounded read-only lanes with first-pass sibling isolation → lineage-aware dedupe → synthesis candidate;

NegotiatedInterdependentInvestigation
  independent whole-question mapping by future workers → disclosed overlap/dependency comparison →
  Task Controller freezes a revised partition → parallel execution with admitted peer deltas →
  cross-review/selective replan → lineage-aware synthesis and verification;

ImplementThenBlindAudit
  one writer → tests → blind cross-family reviewer → correction/probe → final gate;

LiveLearningCampaign
  bounded attempt → instrumented outcome → AttemptLearningDelta →
  admitted task-local overlay revision → exact CampaignLearningStateView →
  next attempt compilation + HarnessActivationReceipt →
  periodic consolidation, promotion or honest stop.
```

`LiveLearningCampaign` is selected when work is long or multi-step, feedback is frequent and competent enough to change strategy, and the next attempt is expected to use the previous outcome. Its minimum profile is one actor, one lineage and one local overlay; population search is not required. Before each materially comparable attempt, Context Compiler builds the exact derived learning-state view from existing owner revisions, then records retrieval/delivery/observable activation against that view. A missing/stale load-bearing owner ref blocks only the dependent compilation. The recipe adds no scheduler, task graph, attempt journal or authority path: the task-local overlay defined in I12.24 is admitted by Governor like any other bounded state, and terminal campaign dispositions never equal task `VERIFIED_COMPLETE`.

Campaign admission records `closure_due_at`, `expires_at`, `closure_owner_ref`, and `terminalization_policy_ref` on the existing Task or Durable Job state; it creates no new scheduler or mutable campaign owner. A campaign cannot remain active indefinitely. At `closure_due_at`, the owner emits `CampaignLearningClosure` or an explicit delayed or inconclusive disposition. At `expires_at`, Governor rejects new overlay revisions and inherited attempts, then terminalizes the campaign to the strongest evidence-supported closure disposition. A missing closure owner is reassigned or escalated; it never leaves an immortal active campaign.

Four functions are separated even when one model performs them sequentially: Actor solves the current task; Refiner analyses experience and proposes the local delta; Evaluator measures the declared property; Promotion Owner decides scope of influence. Role transition creates a new bounded context and capability envelope. Refiner cannot finish the task or promote its own update; Actor cannot edit the evaluator or the retention set. Same-model operation is allowed and explicitly lowers the recorded `IndependenceProfile`.

Later, only after route and recipe evidence:

```text
CompetitiveImplementation;
PathShardedImplementation;
RedTeamAudit;
IncidentDiagnosis.
```

Arbitrary free-form swarms and general DAG builders are not prerequisites. One writer per deliverable is DEFAULT.

### Negotiated decomposition and disclosure boundary

`NegotiatedInterdependentInvestigation` is used only when the task is plausibly cross-cutting and the initial partition itself is uncertain. It does not become a four-agent default and it does not require unanimity.

```text
P1 Independent Mapping
  every future execution lane receives the same high-level question and shared root;
  each independently produces a dependency sketch, unknowns, candidate subquestions and likely overlaps;
  sibling conclusions remain hidden until each mapping is sealed;

P2 Partition Decision
  sealed mappings are disclosed;
  workers identify overlaps, causal cross-boundary dependencies and blind spots;
  the Task Controller records one immutable SwarmPlanDefinition revision and preserved dissent;
  Governor admission remains required; workers cannot mutate the current plan in place;

P3 Parallel Execution
  every attempt executes its frozen work item;
  admitted peer-relevant deltas may be delivered at the next admissible boundary under I10.18;

P4 Cross-review and Selective Replan
  factual conflict, thin evidence, invalidated assumption or omitted observation returns proposed next work;
  the Task Controller opens only the affected branch through a new definition revision and admission;

P5 Synthesis and Verification
  reduction preserves lineage, dissent, coverage gaps and the applicable verifier ceiling.
```

During P1, ordinary peer messages are queued but not disclosed; only an exact safety, authority, privacy or destructive-effect blocker may cross the independence boundary, and that disclosure changes the IndependenceProfile. After P1, receiving a message does not widen write scope, authority, budget, acceptance or plan semantics. A worker may request pause/revalidation, but only the existing coordinator/Governor owners can change execution state.

The recipe begins as a read-only architecture/onboarding/root-cause/security/research profile. Mutating use is promoted only after the coordination ablation and isolated disjoint-worktree canary of I18.11 show a verified benefit without unacceptable harmful redirection, context growth, contamination or merge cost.

### Recipe selection and incremental staffing

Planner chooses the simplest recipe that satisfies task impact and requested assurance. It evaluates:

```text
subtask separability and acceptance independence;
path/schema/state overlap;
need for common sequential history;
merge and coordination cost;
expected evidence diversity and correlated-error risk;
tool/runtime/environment contention;
current route quality, health and quotas;
human attention backlog.
```

Fanout begins at one lane and expands only when the next lane has expected marginal value. Fixed global swarm sizes and static vendor percentages are forbidden defaults.

### Route allocation and failover

Hard constraints are applied before scoring:

```text
required capabilities and exact conformance evidence;
impact/permission and data policy;
local/remote and secret boundary;
route/account health and quota reservation;
worktree/environment compatibility;
independence requirement.
```

Soft score may consider quality, latency, context efficiency, cost/quota pressure and historical outcomes for the task class.

No silent mid-attempt failover. After provider/runtime work has produced meaningful output or an effect, another route creates a new attempt with a sealed handoff and visible causal link.

### Ready Queue and fenced WIP admission

ELIOT maintains two operational projections over canonical work/attention state:

```text
Ready Queue
  executable work whose dependencies and policy are satisfied;

Human Attention Queue
  approvals, questions, conflicts and capacity decisions requiring a person.
```

They are not second task or notification stores. Because canonical work state and Kernel-owned leases/resource claims have different durable owners, admission is a fail-closed saga rather than a fictitious cross-store transaction:

```text
1. AgentCoordinator revalidates dependencies, State Fence, recipe, route evidence and policy.
2. Kernel stages an inactive `AdmissionReservation` in ORS for the exact work item,
   pessimistic cost/quota view, lane, Work/Action and environment claims.
3. Governor commits the canonical `SwarmPlanAdmission`/work-item `ADMITTED` transition,
   admitted attempt identity and launch outbox, referencing the reservation receipt.
4. Kernel activates the reservation and launch authority only after observing the matching
   canonical receipt and unchanged State Fence/Authority Epoch.
5. Launch/provisioning begins. Rejection, timeout or crash before activation cannot launch work;
   an unconsumed reservation is released or reconciled by identity.
```

This uses the same asymmetric principle as authority activation: failure may temporarily reduce capacity, but cannot grant an unrecorded launch. Provider quotas and external environments cannot participate in either local durable transition. Their actual allocation happens later as an idempotent provisioning effect and is reconciled; failure closes that attempt with evidence, releases its active reservation and returns the work through a new admission revision. If capacity is unavailable before admission, work enters `DEFERRED_CAPACITY` with `not_before`/quota reset and does not remain falsely `RUNNING`. Scheduler pulls the next admissible item; no model is required to launch its successor.

### Subscription and portfolio scheduling

Quota windows are first-class and simultaneous: rolling hours, week, month, credits, requests, concurrency and provider-specific limits. Provider meter/invoice outranks ELIOT estimates. Missing usage is `unknown` or `not_exposed`, not zero.

User chooses policy preset and upper envelopes. Governor computes temporary task-class route mix from grounded outcomes and remaining capacity. Strong reviewer/arbitration reserve is not consumed as bulk implementation capacity unless policy explicitly permits it.

### Isolation beyond worktrees

Three independent leases are used:

```text
CodeIsolation
  branch/worktree/path claims;

ProcessIsolation
  Job Object/process group, cwd/env, resource limits and descendant cleanup;

RuntimeIsolation
  ports, services, DB/volumes, browser profiles, caches and remote environment.
```

A mutating/integration lane receives `ExecutionEnvironmentLease` in addition to `WorktreeLease`. Multiple writers require disjoint code invariants, separate mutable runtime resources, sufficient host capacity and a bounded integration plan. Job Objects alone do not isolate ports or service state.

### Blind review and Concilium

Blind reviewer receives a dedicated `BlindAuditPacket`, not the writer's ordinary current packet:

```text
task/acceptance and Architecture constraints fixed before the attempt;
base/candidate diff or artifact;
raw commands/tests/evidence and exact verifier state;
pre-existing negative memory and invariants whose lineage predates the candidate attempt;
explicit coverage gaps and allowed probes.
```

The packet excludes author confidence, self-justification, generated plan/rationale, prose summaries, sibling findings and attempt-created memory unless a later rebuttal/challenge stage discloses them explicitly. Disclosure changes the IndependenceProfile and is recorded. `AuditFinding` requires claim, category/severity, exact evidence, affected resources and optional reproduction/verifier. “Cross-family” or “independent” credit is granted only when `ActualRouteReceipt` and `IndependenceProfile` support it; an unknown actual route may still review, but counts only as a blind non-independent perspective.

First-pass discovery/audit lanes receive one pinned `RootContextRevision` and their own work-item overlay, but not sibling conclusions. The root is immutable for that wave. A change in Architecture, task constraints, critical evidence or shared source creates a new `SwarmWave`; descendants are marked stale or explicitly revalidated, never silently updated in place. After each first-pass result is sealed, challenge/reduce stages may disclose rival findings; from that point the independence profile records the shared information path.

Large result sets are reduced through a bounded `ReductionPlan`, not one giant synthesis prompt:

```text
deterministic schema/provenance validation
→ exact duplicate and shared-lineage grouping
→ bounded first-level reducers
→ challenge/counterevidence stage
→ final synthesis candidate with coverage ledger and dissent.
```

Every reducer has a maximum fan-in, input State Fence and output lineage. Overflow creates another reduction level or a handle; it is never truncated silently.

Disagreement flow:

```text
normalize rival claims and Evidence Lineage
→ run deterministic/discriminative probe if possible
→ if unresolved, arbiter receives only the disagreement packet
→ arbiter selects next observation or records residual uncertainty.
```

Model vote never promotes truth.

### Context and session continuity

Task, work graph, decisions, artifacts and evidence are durable. Runtime process and native session are disposable. Long-lived “personality workers” are not the continuity mechanism.

Rotation triggers include terminal work item, context pressure, repeated correction, route fingerprint change, no progress, security event or role boundary. Cross-runtime transfer uses `Rehydrated` attempt and public inheritance; native resume is only an optimization inside one compatible fingerprint.

Native runtime subagents are allowed only as bounded optimizations behind depth/fanout/tool-inheritance/cancellation/usage policy. Recursive delegation is disabled unless the parent `WorkLease` contains an explicit subtree envelope with maximum depth/fanout, child route classes, cumulative budget, allowed effects, lineage and cancellation cascade. A child cannot enlarge that envelope. Native children never own the ELIOT work graph and their final message is not proof. If a runtime cannot expose child creation, parentage, effective route, usage and cancellation on the exact fingerprint, native delegation is disabled for Material mutation and does not count as independent coverage; an unexpected child becomes a supervision signal and its effects require reconciliation.

`NoLostChildInvariant` is operational rather than rhetorical: the coordinator periodically reconciles admitted descendants against host/provider process/session inventory. Every child has one terminal state—`COMPLETED`, `PARTIAL`, `FAILED`, `CANCELLED`, `UNKNOWN_OUTCOME`, `STALE` or `QUARANTINED`—plus artifact/effect cleanup. A parent cannot finish while a descendant is live, unreachable or has unresolved effects; it may return `PARTIAL/BLOCKED` with explicit child state instead. Watchdog owns independent orphan detection, while AgentCoordinator owns cancellation/reassignment and canonical execution reconciliation.

```yaml
DescendantClosureReceipt:
  parent_attempt_or_swarm_execution:
  admitted_descendant_set_and_lineage_revision:
  observed_runtime_process_session_set:
  terminal_disposition_per_visible_descendant:
  opaque_runtime_parent_disposition:
  artifact_checkpoint_cleanup_and_effect_reconciliation:
  unreachable_or_unknown_descendants:
  observation_coverage_and_blind_intervals:
  parent_finish_ceiling: complete | partial | blocked | unknown_outcome
  coordinator_and_watchdog_evidence_refs:
```

A parent FinishAttempt or swarm terminal transition must reference a current `DescendantClosureReceipt`. Closed runtimes that do not expose descendants are represented as one opaque parent invocation; ELIOT never claims child-level cancellation, budget, independence or cleanup for hidden children.

### Composite run lifecycle and recovery

I14.20 is the single canonical lifecycle vocabulary for ReadyWorkItem, RunAttempt, DurableJob, SwarmPlanDefinition, SwarmPlanAdmission and SwarmExecutionState. The physical state remains with each declared owner; the Fabric uses compatible typed machines rather than one overloaded status field or one new global registry.

`DEFERRED_CAPACITY` belongs only to work admission. It never describes a running attempt or execution state. A `RunAttempt` exists only after `ADMITTED`. External route/environment provisioning is a fallible observed effect after admission; failure releases claims and creates a new admission revision rather than rewriting the old attempt as “not started”.

A parent awaiting deferred child work remains `WAITING_CHILD`; the parent attempt is not capacity-deferred retroactively. Native `completed` is only runtime evidence until ELIOT verifies artifacts/results. Process liveness, logical turn, event cursor and task completion are independent fields.

Progress is new evidence, artifact, accepted patch, resolved finding, verifier result or meaningful state transition—not prose volume. Repeated normalized `(tool,args,error)` and absence of evidence trigger interrupt → diagnosis/replan → cancel/reconcile; unlimited continue/self-repair loops are forbidden.


### Shared-wave disclosure and capability-introduction gate

Each `RootContextRevision` records:

```text
recipient principals/routes;
Disclosure Dependency Closure;
IntroductionSetDigest per recipient/Attempt;
grant-graph and Capability Registry revisions.
```

Adding evidence, a tool/resource facet or a recipient creates a new root revision. Before delivery ELIOT recomputes:

```text
privacy/disclosure coverage;
authority grant paths;
credential binding;
route/provider retention policy;
tool/facet schema exposure.
```

A recipient that cannot receive the broadened root is moved to a private fork, receives a verified redacted projection, is re-authorized/removed, or blocks only the dependent wave. The shared root is never silently widened.

Child attempts receive only introductions inside the admitted subtree envelope. Native child creation that cannot expose exact child lineage, effective route, usage, cancellation and introduction set remains disabled for Material mutation.


### Human control

The role-filtered Human Control Plane may pause/cancel/replan under task authority, change policy/budget only under its owning Human role, approve an exact Critical effect only as Approver, request Concilium, replace Task Controller when authorized, or take over a work item through a new lease. Every intervention is a durable Coordination Event and does not depend on vendor UI state.

