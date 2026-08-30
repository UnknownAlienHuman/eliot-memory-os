## I17.14. Agent Work Unit over a FunctionalCapabilityCell

The primary decomposition unit is a `FunctionalCapabilityCell`; one or more crates are implementation containers, not the source of causal ownership.

```yaml
AgentWorkUnitBrief:
  product_objective_and_causal_property:
  architecture_and_implementation_refs:
  primary_functional_cell:
  implementation_package_and_source_slice_refs:
  effective_micro_module_manifest_ref:
  source_maintenance_owner:
  lifecycle_owner_refs:
  replacement_class_and_iteration_lane:
  proof_latency_profile_ref:
  bounded_support_closure:
  frozen_contract_revision:
  CrateContextCapsule_ref:
  effective_context_profile_and_workset_measurement:
  exact_scope_product_candidate_runtime:
  old_failing_behavior_or_missing_capability:
  hypothesis_and_rivals_if_material:
  discriminator_that_fails_old_behavior:
  ModuleContractKit_and_ModuleTestCapsule:
  one_hop_providers_and_consumers:
  affected_contract_edges:
  BuildFingerprint_and_build_mode:
  allowed_effects_and_non_goals:
  expected_artifact_or_evidence:
  InstrumentProfile_and_proof_ceiling:
  product_pulse_ref:
  budget_stop_and_challenge_path:
  integration_owner:
  writeback:
```

A work unit is small by causal responsibility, authority/effect scope and complete decision context—not by file, crate or support-count quota. The bounded support closure contains exactly the adjacent contracts/source/tests needed to preserve the causal path and is measured by I2.16.

One unit cannot silently change several mutable owners, unrelated public contracts and product status. If a defect crosses owners, Task Compiler creates a Contract/Evidence unit, bounded provider/consumer units, Edge/Integration units and one Product Pulse.

The agent returns `ContractChallenge` when the discriminator measures a proxy, the owner/cell is wrong, the oracle is controlled by the same patch, the complete Decision Safety Floor cannot fit a qualified envelope, or an omitted edge changes the causal explanation. A wider read bundle never grants wider write authority.

