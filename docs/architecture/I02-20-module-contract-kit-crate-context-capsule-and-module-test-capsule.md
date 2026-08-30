## I2.20. Module Contract Kit, Crate Context Capsule, and Module Test Capsule

### `FunctionalCapabilityCell`

A functional cell is a causal decomposition unit, not a sentence-length rule and not automatically a Cargo crate:

```yaml
FunctionalCapabilityCell:
  cell_id:
  purpose_and_user_or_system_property:
  causal_responsibilities:
  lifecycle_owner:
  owned_state_or_explicit_statelessness:
  allowed_effect_classes:
  public_contract_refs:
  independent_proof_surface:
  failure_degradation_and_recovery_boundary:
  replacement_and_rollback_boundary:
  providers_consumers_and_product_pulse:
```

One crate may contain several cells when either: (a) they form a stateless cross-owner contracts/primitives island with no mutable state or effects; or (b) they share one lifecycle owner, one coherent contract/dependency island and one package proof boundary. Several unrelated mutable-state owners, unrelated effect classes or independent rollback boundaries inside one crate trigger `MicroModuleTopologyReview`. A single cohesive cell may remain large when its complete Agent Workset is measurable and independently provable. Package membership never transfers lifecycle authority between cells.

### `EffectiveMicroModuleManifest`

The manifest is generated from Cargo, contract catalogue, Build/Test/Verifier graphs and runtime manifests; it is not another manually maintained authority: One manifest represents one FunctionalCapabilityCell; a crate containing several cells has several manifests.

```yaml
EffectiveMicroModuleManifest:
  manifest_id_revision_and_digest:
  functional_cell_ref:
  source_modules_and_crates:
  lifecycle_owner:
  runtime_owner_and_bundle:
  public_contract_digest:
  owned_state_and_effect_classes:
  execution_contour_and_replacement_class:
  iteration_lane_and_proof_latency_profile_ref:
  physical_source_STU:
  loaded_slice_and_agent_workset_profiles:
  dependency_ports_and_one_hop_providers_consumers:
  independent_proof_entrypoint_and_proof_ceiling:
  affected_edge_profiles:
  product_pulse_ref:
  failure_degradation_recovery_and_removal_boundary:
  current_support_freshness_and_invalidation:
  split_merge_extraction_conditions:
```

### `ProofLatencyProfile`

```yaml
ProofLatencyProfile:
  module_cell_and_proof_profile:
  exact_machine_toolchain_cache_and_build_fingerprint:
  sample_count_warmup_and_contention:
  p50_p95_p99_and_max:
  CPU_RSS_IO_and_queue_wait:
  expected_lane: interactive | normal | slow | manual_release
  qualification_status_expiry_and_invalidation:
```

Missing proof-latency evidence disables automatic assignment to the interactive lane; it does not fabricate failure or force a split. The scheduler may still run the proof as a bounded Durable Job.

### `ModuleContractKit`

```yaml
ModuleContractKit:
  contract_revision:
  crate_or_cell_identity:
  purpose_and_invariants:
  public_types_and_schemas:
  owned_state_and_effects:
  dependency_ports:
  compatibility_rules:
  negative_cases:
  known_unknowns:
  oracle_origins:
```

### `CrateContextCapsule`

```yaml
CrateContextCapsule:
  product_objective:
  functional_capability_cell_refs:
  effective_micro_module_manifest_ref:
  primary_source_package:
  source_token_estimate:
  selected_source_and_tests:
  one_hop_providers:
  one_hop_consumers:
  architecture_implementation_refs:
  failure_fingerprints:
  edge_tests:
  product_pulse:
  omitted_material_and_handles:
  effective_context_profile:
```

### `ModuleTestCapsule`

```yaml
ModuleTestCapsule:
  shape_checks:
  unit_property_model_tests:
  parser_or_golden_corpus:
  fake_port_contract_tests:
  real_edge_profiles:
  fault_restart_replay_cases:
  resource_and_serial_groups:
  proof_level_ceiling:
  known_uncovered_behavior:
  expected_nonzero_test_count:
```

Capsules are generated from Cargo, test, and instrument metadata and supplemented only with non-derivable semantic fields. A crate or cell without an executable `ModuleTestCapsule` may be investigated, but is not independently supported.

### Generated local agent surfaces

Each independently planned crate/module exposes two concise **resource projections** generated from the same contract source:

```text
Contract projection
  purpose, owned state/effects, public invariants, dependency ports,
  compatibility, proof ceiling and promotion/replacement boundary;

Agent-working projection
  one-screen instructions: how to check the unit, exact profile commands,
  prohibited shortcuts, relevant handles and escalation route.
```

The normal surface is a resource/handle compiled into the Agent Workset. `CONTRACT.md` and `AGENTS.md` are optional materializations only for host tools that require local files; ELIOT does not create two files per crate by default. Projections are not separate normative sources. They carry the source contract digest and generator version; stale projections are rejected. Handwritten rationale belongs in Architecture/Implementation records, while commands/test inventory are generated from Cargo and Instrument metadata.

The triad `ModuleContractKit` + `CrateContextCapsule` + `ModuleTestCapsule` is mandatory, not advisory. A capability missing any element cannot have `ImplementationSupport` above `CURRENT_UNVERIFIED`, regardless of code quality or test count: without a contract kit the boundary is undefined; without a context capsule the agent lacks a decision-sufficient workset; without a test capsule there is no independently invocable proof. This directly violates `ARCH-MOD-03`.

