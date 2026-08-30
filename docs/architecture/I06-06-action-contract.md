## I6.6. Action contract

```yaml
ActionContract:
  action_id:
  task_id:
  intent:
  scope_and_state_fence:
  impact_class:
  authority_ref:
  read_set:
  write_or_effect_set:
  preserved_invariants:
  expected_observable:
  verifier:
  rollback_or_compensation:
  stop_conditions:
```

Governor may auto-fill known fields. Agent edits only material uncertainty.

For an external or otherwise effectful action the contract is compiled into three records:

```text
ProposedEffect
  what an agent/component asks to do; no authority;

AuthorizedEffect
  exact proposal + policy/approval/lease/epoch/idempotency and executor boundary;

EffectReceipt
  observed committed/rejected/unknown/compensated outcome.
```

The proposer never executes merely because it produced valid JSON. Replay and simulation can process `ProposedEffect` without performing the effect. Unknown outcome blocks the dependent Ordering Scope until reconciliation; a retry uses the same idempotency identity or a new explicitly related operation after proven rollback.

