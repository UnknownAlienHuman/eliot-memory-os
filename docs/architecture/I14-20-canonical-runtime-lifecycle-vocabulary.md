## I14.20. Canonical runtime lifecycle vocabulary

This is the single normative vocabulary for shared cross-component runtime lifecycles. It is not one physical mutable registry or a second state store. Each machine remains owned by the component named in its contract; this section only prevents incompatible lifecycle meanings.

### Service process

```text
STOPPED → STARTING
STARTING → RECOVERING | READY
RECOVERING → READY | DEGRADED
READY ↔ DEGRADED
READY | DEGRADED → QUIESCING → STOPPED
STARTING | RECOVERING | READY | DEGRADED | QUIESCING → FAILED
FAILED → STOPPED | RESTART_WAIT | QUARANTINED | MANUAL_RECOVERY
RESTART_WAIT → STARTING | QUARANTINED | MANUAL_RECOVERY.
```

Process liveness/readiness and capability-generation state remain separate.

### Write submission and ORS operation

```text
WriteSubmission:
  RECEIVED → NOT_ACCEPTED | STAGED | RESOLVED_EXISTING

ORS Operation:
  STAGED → ASSIGNED → APPLYING → RESOLVED
  STAGED | ASSIGNED | RETRY_WAIT → RESOLVED(cancelled), only with proven no-effect
  APPLYING → RETRY_WAIT → APPLYING
  APPLYING → UNKNOWN_OUTCOME → RECONCILING
  RETRY_WAIT/RECONCILING → RESOLVED | DEAD_LETTER

Final WriteReceipt:
  COMMITTED | REJECTED | CANCELLED | DEAD_LETTER.

`DEAD_LETTER` requires proven no-effect; ambiguous effect remains `UNKNOWN_OUTCOME`
until reconciliation produces a final receipt/disposition.
```

### Task lifecycle and finish decisions

Operational task state and the outcome of one finish attempt are separate machines.

```text
TaskLifecycle:
  PROPOSED → OPEN → FRAMED → ACTIVE ↔ VERIFYING
  ACTIVE | VERIFYING → SUSPENDED | BLOCKED
  SUSPENDED | BLOCKED → ACTIVE
  any non-closed state → CLOSING → CLOSED
  CLOSED → REOPENED → ACTIVE.

FinishDecisionOutcome:
  VERIFIED_COMPLETE | PARTIAL | BLOCKED | FAILED_VERIFICATION |
  DEGRADED_NO_PROOF | UNSAFE_TO_FINISH | CANCELLED | SUPERSEDED.
```

Mapping rules:

```text
VERIFIED_COMPLETE
  → closes the task as completed only with applicable proof;

CANCELLED / SUPERSEDED
  → close after authorized disposition of completed work and external effects;

PARTIAL
  → normally leaves the task SUSPENDED/ACTIVE with explicit coverage;
    it closes incomplete work only when the Requester/Task Controller explicitly
    requests that disposition and no unresolved effect requires continued supervision;

BLOCKED
  → sets operational state BLOCKED and records the unblock condition;

FAILED_VERIFICATION
  → keeps the task ACTIVE or BLOCKED with failed evidence and next corrective action;

DEGRADED_NO_PROOF / UNSAFE_TO_FINISH
  → do not close the task as done; they preserve a blocked/suspended state and next action.
```

`REOPENED` is a new lifecycle revision, not a rewrite of the prior `FinishDecision`. Every closure/reopen preserves the acceptance ledger, effects, evidence and causal link.

### Ready work admission

```text
BLOCKED_DEPENDENCY → READY
READY → ADMITTED | DEFERRED_CAPACITY | CANCELLED | STALE
DEFERRED_CAPACITY → READY | CANCELLED | STALE.
```

### Admission reservation

```text
STAGED_INACTIVE → ACTIVE | RELEASED | EXPIRED | RECONCILING
RECONCILING → ACTIVE | RELEASED | EXPIRED
ACTIVE → RELEASED | RECONCILING.
```

`ACTIVE` requires the exact canonical admission receipt, unchanged State Fence and matching Authority Epoch. `STAGED_INACTIVE` may reserve bounded internal capacity but cannot provision or launch. `RECONCILING` cannot create a new effect. Release, expiry and recovery reuse the same reservation identity and produce a receipt; an active reservation attached to a nonterminal attempt cannot be expired as cleanup.

### Swarm definition, admission and execution

```text
SwarmPlanDefinition lifecycle:
  DRAFT → FROZEN → SUPERSEDED | CANCELLED;

SwarmPlanAdmission lifecycle:
  PENDING → ADMITTED | REJECTED | STALE | CANCELLED | SUPERSEDED;

SwarmExecutionState lifecycle:
  NOT_STARTED → RUNNING ↔ PAUSED → REDUCING → VERIFYING
  → COMPLETED | PARTIAL | FAILED | CANCELLED | UNKNOWN_OUTCOME.
```

Task Controller alone authors definition revisions. `FROZEN` is immutable and is the only revision that can be admitted. Governor alone records admission disposition for an exact frozen definition. AgentCoordinator advances execution only under `SwarmCoordinatorLease` and the matching active admission. Changing objective, acceptance, ceilings, work-graph semantics or stop conditions creates a new draft/frozen definition plus a new admission and an explicit drain/cancel disposition for the old execution. Staleness of an execution result is a separate applicability disposition; it never rewrites what the execution actually did.

### Live peer message delivery

```text
DRAFT → ADMITTED → QUEUED
QUEUED → DELIVERED | STALE | EXPIRED | CANCELLED
ADMITTED → STALE | CANCELLED.
```

`DELIVERED` means the exact admitted delta reached a route-qualified admissible boundary. Recipient acknowledgement, public use and later outcome-helpfulness are separate observations and never rewrite this lifecycle. A sender does not wait for them. A plan/State-Fence mismatch marks the queued item `STALE`; it is not silently retargeted.

### Anchored review item

```text
DRAFT → PENDING_DELIVERY → DELIVERED
DELIVERED → ANSWERED | STALE | SUPERSEDED
ANSWERED → RESOLVED | REJECTED_WITH_REASON | STALE | SUPERSEDED
PENDING_DELIVERY → STALE | SUPERSEDED.
```

Delivery/answer does not imply resolution. `STALE` preserves the original target and current resolver result. `SUPERSEDED` points to the replacement item/revision. A batch is a derived envelope and has no separate lifecycle.

### Run attempt

```text
ADMITTED → PROVISIONING → LAUNCHING → RUNNING
↔ WAITING_TOOL | WAITING_HUMAN | WAITING_CHILD | CHECKPOINTED
→ VERIFYING → AUDITING
→ COMPLETED | PARTIAL | FAILED | CANCELLED | UNKNOWN_OUTCOME.
```

Attempt execution history is never rewritten to `STALE`. If its State Fence, route evidence or parent-plan revision becomes invalid, a separate result/applicability disposition marks the produced evidence/artifact stale and prevents proof/integration. The attempt still records what actually ran and how it ended; a new admitted attempt performs replacement work.

### Integration candidate

```text
PROPOSED → READY | STALE | REJECTED
READY → INTEGRATING | STALE | REJECTED | CONFLICTED
INTEGRATING → ACCEPTED | REJECTED | CONFLICTED | UNKNOWN_OUTCOME
UNKNOWN_OUTCOME → ACCEPTED | REJECTED | CONFLICTED, only through reconciliation evidence.
```

Only the holder of the current `IntegrationLease` may enter `INTEGRATING`. `ACCEPTED` requires governed apply plus post-apply verification. Unknown external/Git/artifact outcome never becomes `REJECTED`; it remains `UNKNOWN_OUTCOME` until reconciled.

### Durable Job execution

```text
NOT_STARTED → QUEUED → LEASED → RUNNING ↔ CHECKPOINTED
→ VERIFYING
→ COMPLETED | PARTIAL | FAILED | CANCELLED | UNKNOWN_OUTCOME.
```

Execution outcome is immutable history. A separate applicability/freshness disposition may mark its outputs stale for a new State Fence, route or parent revision; it does not rewrite the job outcome to `STALE`.

### Session

```text
ATTACHING → ACTIVE ↔ SUSPENDED → DETACHED | EXPIRED | REVOKED.
```

### Authority activation and token projection

`CapabilityToken` is a compact compatibility/transport projection of currently activated authority; it is not the parent-lineage owner defined in I6.15.

```text
PROPOSED → PENDING_KERNEL_ACTIVATION → ACTIVE
ACTIVE → EXPIRED | REVOKED | SUPERSEDED
PENDING_KERNEL_ACTIVATION → REJECTED | CANCELLED | STALE.
```

Only `AuthorityActivationReceipt` enters `ACTIVE`. ORS revocation takes effect before canonical reconciliation and cannot be reversed by replaying an older token record.

### Capability grant lifecycle

```text
PROPOSED → PENDING_KERNEL_ACTIVATION → ACTIVE
ACTIVE → REVOKED | EXPIRED | STALE
PENDING_KERNEL_ACTIVATION → REJECTED | CANCELLED | STALE
ACTIVE --narrow by a new grant revision and activation receipt--> ACTIVE.
```

A grant cannot enter `ACTIVE` unless its parent path is active and the child set is a strict subset/intersection. Narrowing creates a new immutable grant revision/receipt; it is not a mutable `NARROWED` lifecycle state. Widening or restoration requires a new grant/epoch. Graph revision changes invalidate derived effective snapshots. Regrant after revocation creates a new grant/epoch; it does not reactivate the old record.

### Capability introduction lifecycle

```text
REQUESTED → COMPILED → ACTIVE
ACTIVE → SUSPENDED | REVOKED | STALE | CONSUMED | EXPIRED
COMPILED → REJECTED | STALE.
```

`ACTIVE` requires matching supporting grants, registry revision, State Fence, credential binding and FacetManifest. Introduction does not survive holder/session/epoch change.

### Disclosure closure and decision lifecycle

```text
closure:
  COMPUTING → COMPLETE | PARTIAL | UNKNOWN
  COMPLETE | PARTIAL | UNKNOWN → STALE | SUPERSEDED

decision:
  REQUESTED → ALLOW | ALLOW_REDACTED | RECOMPUTE_NARROWER |
              FORK_PRIVATE | REQUIRE_AUTHORITY | DENY
  any issued decision → STALE | REVOKED | SUPERSEDED.
```

A change in source domain, ACL/policy, recipient/route, State Fence or declassifier validity invalidates the exact decision and its compiled packet/bundle. Historical delivery receipts remain immutable. `PARTIAL` or `UNKNOWN` never defaults to external allow.

### Blueprint instance

```text
PROPOSED → VALIDATING → BINDING → CONFORMANCE
→ STAGED → ACTIVE
ACTIVE → UPDATING | DRAINING | REVOKED
UPDATING → ACTIVE | ROLLED_BACK | FAILED
DRAINING → RETIRED
any pre-active state → REJECTED | FAILED.
```

Blueprint instance state is a projection over normal component/module generation and binding receipts; it is not a second deployment authority.

### Lease

```text
REQUESTED → ACTIVE → RELEASED | EXPIRED | REVOKED | SUPERSEDED
ACTIVE --renew with a new lease revision/expiry and the same lineage--> ACTIVE.
```

### Module generation

```text
DISCOVERED → STAGED
STAGED → STARTING | RETIRED | QUARANTINED
STARTING → RECOVERING | READY | FAILED
RECOVERING → READY | DEGRADED | FAILED
READY → ACTIVE | DEGRADED | QUIESCING
ACTIVE ↔ DEGRADED
ACTIVE | DEGRADED → QUIESCING → DRAINED → STOPPED → RETIRED
FAILED → RESTART_WAIT → STARTING | QUARANTINED | MANUAL_RECOVERY.
```

### Generation cutover

```text
PREPARING → ARMED → COMMITTED → RECONCILING → COMPLETED
PREPARING/ARMED → FAILED
COMMITTED/RECONCILING → COMPLETED | FAILED_REQUIRES_FORWARD_CUTOVER.
```

Rollback is never a backward state transition. It is a new cutover with a newer Authority Epoch. `COMMITTED` is the ORS linearization point; unresolved scopes remain explicit during reconciliation.

### Kernel activation

```text
IDLE → SHADOW_NO_AUTHORITY → HANDOFF_PREPARED → OLD_TERMINATED
→ NONCE_ISSUED → ACTIVATING → ACTIVE
any pre-active state → FAILED | MANUAL_RECOVERY.
```

Only HostStateJournal plus exclusive KernelOwner/ORS locks may advance this machine. A failed candidate never inherits the old Kernel epoch, and restore never revives an activation record as current authority.

### Claim

Epistemic status and lifecycle are independent:

```text
observed → supported → verified;
any → contested | stale | superseded | rejected;
active → dormant | suppressed | archived | quarantined.
```

Privacy erasure is a separate purge-ledger process.

### Problem/Incident

```text
OPEN → TRIAGED → DIAGNOSING | CONTAINED | REPAIRING
→ VERIFYING → RESOLVED | ACCEPTED_RISK | SUPERSEDED | QUARANTINED.
```

New evidence may reopen. Identical labels in different typed machines are not interchangeable; serialized state always includes machine kind and schema version.

