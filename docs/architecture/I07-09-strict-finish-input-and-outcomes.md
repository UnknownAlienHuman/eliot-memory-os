## I7.9. Strict finish input and outcomes

The public finish surface accepts only a candidate request:

```yaml
FinishAttemptDraft:
  task_id:
  expected_task_revision:
  requested_outcome:
  artifact_refs:
  observation_refs:
  verifier_run_refs:
  remaining_unknowns_declared_by_caller:
  rationale_candidate:
```

The caller does not submit `CompletionProof`. The Finish service rehydrates the current TaskContract, acceptance items, exact artifacts, current State Fence, executed verifier runs and effect outcomes, then derives:

```yaml
DerivedCompletionProof:
  task_and_revision:
  per_acceptance_coverage:
  artifact_and_verifier_bindings:
  checks_not_executed_or_stale:
  unresolved_effects_and_unknowns:
  proof_ceiling:
  derivation_digest:
```

A legacy caller-supplied proof is rejected with `LEGACY_FINISH_INPUT_REJECTED`; absence of strict fields never selects a weaker path. A verifier with execution status `NOT_EXECUTED` or `SIMULATED`, stale scope, missing artifact binding or unknown outcome cannot support `VERIFIED_COMPLETE`.

The closed `FinishDecisionOutcome` set remains:

```text
VERIFIED_COMPLETE;
PARTIAL;
BLOCKED;
FAILED_VERIFICATION;
DEGRADED_NO_PROOF;
UNSAFE_TO_FINISH;
CANCELLED;
SUPERSEDED.
```

Only `VERIFIED_COMPLETE` means done. Every other outcome lists completed artifacts/effects, uncovered acceptance items, material unknowns and continuation/rollback. A job result never sets this enum directly.

A `Stop`, disconnect, non-response, truncated output or parse failure is never a FinishDecision. A durable `StopBoundaryRecord` closes new admissions at one revision and records:

```text
stop/interrupt identity and time;
task/attempt/state fence and event cursor;
in-flight operations and child attempts;
external-effect dispositions;
last durable/normalized/applied event;
required checkpoint, reconciliation or finish action.
```

The mandatory `StopHookForgeryTest` proves that caller text or a forged hook event cannot mint this record, a DerivedCompletionProof or a terminal task outcome.

