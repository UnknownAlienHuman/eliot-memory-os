## I12.36. Memory threat handling and Environment Runbooks

`MemoryThreatProfile` is a composable assessment attached to candidate/admitted memory and derived views. Initial threat kinds preserve the old donor distinctions without making them a universal scalar:

```text
wrong_scope; stale; contradicted; duplicate; overbroad;
instruction_injection; tool_definition_drift; poisoned_lineage;
sycophantic_or_authority_laundering; negative_transfer; privacy_boundary;
unknown_due_to_incomplete_lineage.
```

Each assessment carries evidence, confidence/unknowns, affected influence, default handling proposal and clearance/reactivation route. Handling may be `warn`, `require_revalidation`, `suppress`, `quarantine`, `revoke_influence`, `preserve_as_counterevidence` or `ask`. The final transition follows authority and policy; similarity alone cannot create a hard blocker or purge.

`MemoryAuditSuspension` is represented as a reversible hot-path suspension inside the normal lifecycle: the item remains addressable for audit, retains provenance and has an owner plus release condition. It is not physical erasure and does not silently alter factual support.

Operational procedural memory uses `EnvironmentRunbook`:

```yaml
EnvironmentRunbook:
  environment_service_or_tool_scope:
  setup_and_preconditions:
  health_and_readiness_checks:
  common_failures_and_normalized_signatures:
  bounded_recovery_steps:
  where_applies_and_where_not_apply:
  required_authority_effects_and_secrets:
  expected_observables_and_verifiers:
  last_verified_state_fence:
  evidence_owner_and_lifecycle:
```

A runbook is not an executable permission. It may be proposed by Dreamer or derived from repeated grounded episodes, but execution uses normal Action/Recovery contracts. It becomes stale when environment generation, credentials, policy, Tool Definition, dependency or verifier changes.

Environment runbooks, residual experience and professional methods are retrieved by exact scope/cue first. They are demoted or split when transfer produces errors; they are never promoted solely because the same prose appeared repeatedly.



