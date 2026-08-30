## I14.27. Capability Blueprint and independent instance lifecycle

A `RecipeManifest` describes orchestration. A `CapabilityBlueprint` packages a reusable micro-module composition without exporting live authority or user state. Governor owns blueprint catalogue/provenance and instance admission; Kernel owns only resulting generation activation/fencing; no blueprint package is an authority token.

```yaml
CapabilityBlueprint:
  blueprint_id_and_version:
  title_purpose_output_kinds:
  origin_and_provenance_chain:
  component_graph:
  license_sbom_and_dependency_policy:
  artifact_contract_and_interface_digests:
  facet_and_binding_requirements:
  state_schema_and_migration_contract:
  conformance_and_ModuleTestCapsule_refs:
  verifier_requirements:
  compatibility_and_removal_boundary:
  package_hash_signature_and_size_limits:
```

A blueprint explicitly excludes:

```text
credentials and secret handles;
active grants/tokens/leases/epochs;
canonical project memory;
live task/module state unless exported as a separate governed data package;
chat history or hidden reasoning;
Route Continuation State;
user-specific route/account bindings;
unresolved external effects;
owner-specific policy expansion.
```

Instantiation creates an independent instance:

```yaml
BlueprintInstance:
  instance_id:
  blueprint_digest:
  WorkScope_and_instantiating_principal:
  resolved_binding_refs:
  independent_generation_refs:
  independent_state_root_or_snapshot:
  local_policy_and_authority_refs:
  instantiation_receipt:
  fork_update_lineage:
```

Saga:

```text
verify immutable package/signature/provenance/license/SBOM;
validate Architecture/Implementation/interface and dependency-policy compatibility;
resolve each binding through Capability Introduction;
run common conformance and real-runtime namespace tests;
create independent state/generations;
activate through normal Module/Generation cutover;
retain blueprint digest for migration, revocation and vulnerability invalidation.
```

Publishing a new version never mutates an existing blueprint. Same semantic version with a different digest is rejected. Forks receive new identity and preserve origin lineage.

Two sharing modes remain distinct:

```text
share live state
  → ordinary authority, disclosure and collaboration contracts;

share blueprint
  → state/credential-free package that creates another independent instance.
```

Blueprint implementation is deferred until Operational Spine Proof 1 and one component has completed the WASM/native promotion proof. The contract exists now so Recipe, ModuleCatalog and external package work do not collapse into one ambiguous object.


