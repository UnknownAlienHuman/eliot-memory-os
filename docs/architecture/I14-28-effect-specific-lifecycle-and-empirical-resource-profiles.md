## I14.28. Effect-specific lifecycle and empirical resource profiles

Canonical intent and external effect are separate state machines. Every effect class declares:

```yaml
EffectClassContract:
  class_id:
  issue_owner:
  identity_schema:
  provider_idempotency: NONE | CONDITIONAL | GUARANTEED_FOR_SCOPE
  observation_method:
  reconciliation_method:
  compensation_method_and_limit:
  timeout_disposition: UNKNOWN_OUTCOME
  verifier_and_proof_ceiling:
```

Lifecycle:

```text
PREPARED → AUTHORIZED → ISSUED
         → ACKNOWLEDGED | UNKNOWN_OUTCOME
         → OBSERVED
         → RECONCILED | COMPENSATED | IRREVERSIBLE_RESIDUE.
```

A sequence gap, timeout, process exit or canonical receipt never proves `no effect`. Generic rollback claims are forbidden; compensation is effect-specific and may leave residue.

Queue capacities, timeouts, retry budgets and Control Reserve sizes are `EmpiricalParameter`s. Before qualification they are conservative planning hypotheses. Qualification records arrival/service distributions, burst and fan-out, p95/p99 latency, saturation, starvation, restart storms, control-lane preservation, error/unknown-outcome rates and a kill condition. No one number is a universal liveness guarantee.


External-effect truth is grounded in sink-owned evidence where the sink supports it:

```yaml
EffectAcceptanceEvidence:
  effect_and_provider_idempotency_identity:
  arrival_and_claim_fence:
  sink_acceptance_or_provider_receipt:
  independent_readback_or_observation:
  acknowledgement_semantics:
  reconciliation_attempts:
  outcome: ACCEPTED | REJECTED | UNKNOWN | IRRECONCILABLE
  compensation_or_residue:
```

A client-side WAL, send success or acknowledgement cannot resolve whether the sink accepted a write unless the effect contract explicitly defines that acknowledgement as authoritative. Crash recovery therefore queries sink-owned acceptance/readback before retry; `IRRECONCILABLE` remains visible and cannot be converted to `not_committed`.


