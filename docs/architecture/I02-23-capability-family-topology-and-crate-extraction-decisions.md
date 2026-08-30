## I2.23. Capability-family topology and crate extraction decisions

Implementation fixes responsibility families, not a target count or frozen list of crate names. The current families are:

```text
foundation and public contracts;
Host, Kernel and platform lifecycle;
Governor task, authority and canonical transitions;
store, blob, export, migration and recovery;
Instrument/test execution and evidence normalization;
memory, context, understanding and derived projections;
Watchdog, Doctor, Dreamer and Meta;
agent routes, coordination and bounded swarm;
human/agent surfaces and optional domain/vendor/research contours.
```

Root `default-members` contains only primary binaries, contracts, Kernel/Governor core, primary store path, Instrument Plane baseline, the first agent route and short local proofs. Vendor bridges, coverage/mutation/fuzz, heavy code-index pilots, cloud/AWS, Researcher providers, professional modules, benchmark corpora and experimental actor/WASM/distributed routes remain outside the root default command unless a current work profile needs them.

### Crate admission and merge criteria

A separate crate is preferred only when an executable contract/test/context seam exists and an explicit `CrateExtractionDecision` predicts net benefit. Strong admission grounds are:

```text
independent public or inter-layer contract;
independent unit/property/model-test seam;
separate owner or bounded agent work item;
different dependency, security or license profile;
materially different change cadence;
multiple real consumers;
heavy optional dependency island;
measurable context/rebuild blast-radius reduction;
replaceable implementation boundary;
own pure state machine or causal responsibility.
```

The expected agent seam is concrete: a bounded route can read the capability with its contract/tests, change one causal responsibility, run package-local proof, see one-hop consumers/providers and avoid loading unrelated subsystems.

The following normally remains an ordinary Rust module:

```text
private helper without an independent contract;
small type group used by one parent;
implementation always changed and tested with its owner;
file split only for navigation;
algorithm fragment without an independent reason to change.
```

Crates should merge when most of these conditions hold:

```text
they almost always change in one work unit;
no independent consumer or test selector exists;
one is a pass-through of the other;
manifest/API overhead exceeds context savings;
private mutable state is repeatedly threaded across the boundary;
the split creates cyclic adapter/facade construction;
there is no measured build, fault, dependency or agent blast-radius benefit.
```

Crate-per-file and crate-per-type are prohibited proxy goals. A new package without a real consumer/test seam is rejected unless it is a time-bounded migration facade with an owner, expiry and removal test.

### Canonical extraction decision

```yaml
CrateExtractionDecision:
  affected_functional_cells_and_lifecycle_owners:
  current_source_dependency_and_change_closure:
  proposed_package_boundary:
  public_contract_and_independent_test_entrypoint:
  first_real_consumer_or_time_bounded_migration_facade:
  source_maintenance_owner_and_vendor_type_boundary:
  dependency_security_license_and_build_isolation:
  expected_agent_workset_context_and_reverse_fanout_delta:
  expected_compile_test_integration_and_release_cost_delta:
  migration_reexport_rollback_removal_and_expiry:
  counter_risks_merge_or_rejoin_condition:
  evidence_status_and_review_owner:
  disposition: keep | split | merge | extract_contract | isolate_dependency | experiment
```

A proposed name or presence in a research document is not an implementation task. Historical names and extraction hypotheses live in the external cold backlog until a measured change closure activates them.

### Workspace and fleet evidence

`WorkspaceScaleProfile` is an empirical vector over the actual workspace; it has no universal `small/medium/large` package-count threshold:

```yaml
WorkspaceScaleProfile:
  package_target_feature_and_build_script_counts:
  metadata_and_rust_analyzer_load:
  clean_incremental_and_package_selective_build_distributions:
  reverse_fanout_and_typical_change_closure:
  test_inventory_and_sharding_cost:
  shared_target_cache_and_io_contention:
  parallel_agent_throughput_and_merge_cost:
  manifest_contract_and_orientation_burden:
  validity_scope_expiry_and_countermetrics:
```

Generated `CrateFleetReport` adds source/context footprint, public API surface, change/co-change frequency, reverse fan-out, cold/warm compile and critical-path time, test discovery/execution cost, dependency/feature weight, defect attribution, agent success/repair escapes and runtime-bundle mapping. Its `ContractSurfaceProfile` records applicable contracts/owners, agent-visible contract tokens, one-hop edges, generated/manual duplication, proof latency, Product Pulse dependency and wrong-owner incidents.

`WorkspaceScaleReview` opens when package-selective work repeatedly reaches a wide closure, metadata/rust-analyzer latency blocks interactive work, target/cache contention appears, feature unification causes incompatible rebuilds, typical changes cross many owners, or added parallel lanes no longer improve throughput.

A scalar may sort candidates but cannot authorize split or merge. A split is rejected when it reduces source size while increasing contract surface, ceremony or wrong-owner rate. A merge is rejected when it removes independent proof or replacement. Topology changes are admitted only when context/build/test/ownership outcomes improve without material regression in Product Pulse, dependency clarity, recovery or agent correctness.

### Capability cell registry

`FunctionalCapabilityCell` is enumerable, not only referenced. A generated `CapabilityCellRegistry` is compiled from `[package.metadata.eliot].functional_cell_refs`, Module/service manifests and the contract catalogue:

```text
cell id and revision;
one-line causal responsibility;
owns: contract surface, mutable state or explicit statelessness, effects;
must not own: explicit non-responsibilities;
runtime layer and execution contour;
replacement class and iteration lane;
independently invokable proof entrypoint;
one-hop providers and consumers;
current support and invalidation set.
```

The registry is the answer to “how many cells exist and who owns what” without reading this chapter. It is generated: prose never maintains a parallel list. A cell without a proof entrypoint, with an undeclared state owner or with a second owner for the same mutable state is a registry defect, not an acceptable variant.

A crate may host several cells and one cohesive cell may span several crates; the registry keeps both mappings explicit so source packaging and causal ownership never silently merge.

