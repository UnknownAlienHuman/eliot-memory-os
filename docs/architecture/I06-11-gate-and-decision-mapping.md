## I6.11. Gate and decision mapping

Different control questions keep different result types. A universal `verdict` enum is forbidden because it would erase distinctions between admission, action authority, memory influence, finish and lifecycle.

Shared metadata:

`DecisionEnvelope<T>` is an ephemeral request/response projection. Durable facts remain in the corresponding `PolicyDecision`, `WriteReceipt`, `FinishDecision`, lease, approval, Problem/Conflict/Attention or lifecycle receipt; a transport response is never a second decision ledger.

```yaml
DecisionEnvelope:
  decision_id:
  decision_kind:
  result:                # typed by decision_kind
  reason_codes:
  evidence_and_blocking_refs:
  state_fence:
  authority_or_lease_ref:
  next_allowed_action:
  recovery_or_conflict_directive_ref:
```

Closed typed results:

```text
WriteAdmissionDecision
  admitted | admitted_candidate | not_accepted | conflict;

MemoryAdmissionDecision
  include_exact | include_handle | include_with_warning |
  require_revalidation | suppress | quarantine;

NegativeMemoryDecision
  no_match | warn_similar | require_discriminative_probe |
  block_exact_repeat | reopened_with_evidence;

ActionDecision
  allowed | allowed_read_only | require_probe |
  require_refresh | require_approval | denied;

FinishDecision
  VERIFIED_COMPLETE | PARTIAL | BLOCKED | FAILED_VERIFICATION |
  DEGRADED_NO_PROOF | UNSAFE_TO_FINISH | CANCELLED | SUPERSEDED;

LifecycleDecision
  applied | accepted_for_canary | deferred | rejected.
```

Only `block_exact_repeat` may produce `ActionDecision.denied` from failure memory without another policy/decision, and only under a registered deterministic trigger in matching scope. Similarity alone warns or requires probe.

A model may propose inputs or explanation. Decision owner and transition path remain deterministic/policy/Human as declared. Ownership is split without creating two semantic gates:

```text
eliotd/Governor
  owns semantic admission, memory influence, action applicability,
  finish and lifecycle meaning;

Kernel
  rechecks principal, capability token, impact/effect ceiling,
  State Fence, Authority Epoch, operation identity and generation;

store bridge
  enforces named-operation/transition-class ceilings and atomic persistence only.
```

Legacy gate names are compatibility projections documented in the donor migration audit, not canonical result types.

