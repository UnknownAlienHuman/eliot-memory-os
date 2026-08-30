## I10.18. Mailbox, blackboard, live peer delivery and anchored review

### Mailbox

Durable directed coordination:

```text
at-least-once delivery;
ordered sequence per recipient/task;
message-id idempotency;
ack for control messages where the contract requires it;
large payload by handle;
expiry/reassignment after Session loss;
route-qualified delivery capability and visible degradation.
```

Message kinds:

```text
assignment;
checkpoint;
question;
conflict notice;
result;
verifier result;
cancel/supersede;
attention/escalation;
live peer delta;
anchored review item/batch.
```

The common `EventEnvelope`/`ReceiptEnvelope` owns identity, sender/recipient principal, timestamps, ordering, provenance, privacy/disclosure, State Fence and delivery receipts. Payload records below do not duplicate those fields.

### Coordination map

A worker addresses peers through the derived `CoordinationMapView` from I10.15:

```text
work-item identity and one-line responsibility;
dependency/overlap edges;
assigned attempt and role;
mailbox route handle;
current frozen plan/wave revision.
```

It is rebuilt from the frozen plan and current assignments. It is not an `AttemptInterestSet`, semantic subscription engine, new scheduler or mutable routing owner. Initial routing is explicit by attempt/work-item reference; automatic semantic subscriptions remain an experiment until measured need.

### Live peer message

```yaml
LivePeerMessagePayload:
  sender_attempt_and_work_item:
  recipient_attempt_or_work_item_refs:
  frozen_plan_and_wave_revision:
  kind: relevant_finding | assumption_invalidated | dependency_discovered |
        plan_contradiction | obstacle | abandoned_dead_end
  concise_delta:
  evidence_and_artifact_handles:
  requested_reaction: inform | revalidate | reply | pause_dependent_effect
  urgency: normal | before_next_dependent_effect
  dedup_key_and_expiry:
  delivery_policy: next_admissible_boundary
```

Sender semantics:

```text
sender waits for durable mailbox admission of the message;
sender does not wait for recipient acknowledgement, response or plan revision;
current model/tool step is never interrupted;
no full thread/transcript snapshot is attached by default;
only the bounded delta plus exact expansion handles is delivered.
```

Delivery profile:

```text
EventIntegrated
  inject an admitted delta before the next model/tool step when the host exposes a safe boundary;

ToolOnly
  include it in the next ELIOT response/turn boundary;

OfflineWorker
  deliver at the next checkpoint, relaunch or explicit coordinator boundary;

Unavailable
  retain the mailbox item, expose the delivery capability gap and do not claim passive awareness.
```

The Context Compiler admits a live delta only after checking recipient/work-item relevance, exact plan and State Fence, privacy/disclosure, evidence availability, novelty/deduplication, urgency, payload budget and first-pass independence policy. An `assumption_invalidated`, `plan_contradiction` or `before_next_dependent_effect` message may create a revalidation/pause obligation, but it creates no truth, authority, finish, plan revision or write-scope expansion.

Delivery, recipient acknowledgement, public use in a decision/artifact and outcome-helpfulness are separate observations. A message can be delivered and ignored, used and harmful, or helpful only under a later outcome comparison. These states are never collapsed into one success flag.

### Blackboard

Shared typed facts/candidates for a task or swarm:

```text
FindingCandidate;
EvidenceHandle;
Unknown;
HypothesisCandidate;
ConflictNotice;
DecisionRequest;
VerifierResult;
ArtifactHandle;
Blocker.
```

It is not a transcript or free-form group chat. Blackboard items retain author, lineage, State Fence and lifecycle. A live peer message may point to a blackboard item but does not duplicate or silently promote it.

### Anchored review items

`AnchoredReviewItem` is durable review coordination under the existing coordination/attention path. It creates no new store, scheduler, task graph or authority owner.

```yaml
AnchoredReviewItem:
  review_item_id:
  author_principal:
  target_kind: public_message | public_plan | public_rationale |
               tool_result | diff | source | verifier_result
  original_target_revision_and_anchor:
  kind: question | correction | objection | requested_change |
        missing_evidence | scope_issue | acceptance_issue
  content:
  state_fence:
  lifecycle: draft | pending_delivery | delivered | answered |
             resolved | rejected_with_reason | stale | superseded
  response_change_and_verifier_refs:
```

`ReviewBatch` is a derived delivery envelope over several independent items submitted together. It has no independent lifecycle owner. Every item receives its own disposition; unresolved items remain visible obligations and cannot disappear because the surrounding message was answered.

Rules:

```text
review targets are public artifacts, public rationale, exact code/diff/tool/verifier surfaces only;
hidden chain-of-thought is neither persisted nor a review target;
original revision/anchor is immutable history;
current-location resolution uses I10.21 and remains exact/moved/modified/ambiguous/stale/deleted/unavailable;
ambiguous resolution never silently attaches to the most similar fragment;
a comment/request does not grant write/effect/goal/acceptance authority;
rejection requires a reason; requested change requires normal owner, effect and verifier paths;
resolution of a review item is distinct from acknowledgement or delivery.
```

Anchored review may escalate a real blocker to the existing Problem/Conflict/Critical-Attention owner, but it is not itself a second problem or approval system.

