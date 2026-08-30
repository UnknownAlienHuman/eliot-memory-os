## I16.22. Contract and documentation burden

`ContractSurfaceProfile` and `DocumentationBurdenReceipt` make the system's own specification cost visible:

```yaml
ContractSurfaceProfile:
  work_family_and_route_profile:
  applicable_contract_owner_count:
  rendered_instruction_contract_and_tool_tokens:
  expansion_handle_count_and_usage:
  stale_or_conflicting_projection_count:
  contract_change_fanout:
  generated_vs_manual_definition_ratio:
  orientation_time_contract_challenges_and_wrong_owner_events:
  proof_and_product_pulse_dependencies:

DocumentationBurdenReceipt:
  changed_document_and_contract_digests:
  added_removed_or_generated_surface:
  affected_agent_profiles_and_consumers:
  measured_task_or_recovery_delta:
  simplification_merge_or_retirement_candidates:
```

No scalar becomes a target. The purpose is to detect when additional precision increases cognitive/operational burden without improving correctness, recovery or product outcome. In that case the default response is to simplify, merge, generate or remove stale prose — not to add another rule layer.

