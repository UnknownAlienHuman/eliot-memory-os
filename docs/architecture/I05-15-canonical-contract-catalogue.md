## I5.15. Canonical contract catalogue

The versioned contract catalogue/IDL is the single catalogue of load-bearing public and durable contracts. **No generated authoritative catalogue exists yet; `ImplementationSupport = TARGET` and `EvidenceExecutionStatus = NOT_EXECUTED`.** Until a real generated catalogue is consumed by current source/tests and bound evidence, the owning I-section remains authoritative for meaning, owner, behavior and failure semantics.

Appendices N/P/H are target/discoverability projections. They cannot override an owning I-section, create support by presence, or become a second field-level schema owner.

```yaml
ContractCatalogueEntry:
  contract_name_and_kind:
  single_owning_section:
  owner_capability_and_state_owner:
  contract_revision_and_digest:
  generated_schema_trait_and_surface_refs:
  projection_index_refs:
  implementation_support_and_proof_ceiling:
  compatibility_migration_and_invalidation:

ContractCatalogueBuildReceipt:
  implementation_and_architecture_digests:
  discovered_normative_contracts_and_owners:
  generated_IDL_code_schema_and_surface_refs:
  unresolved_manual_or_duplicate_definitions:
  consumer_coverage_and_current_support:
  build_tool_and_artifact_digests:
```

Only blocks explicitly marked `ContractShape: normative` require an entry; unmarked YAML/examples are explanatory target projections. A missing entry for a marked contract makes coverage `PARTIAL`; a second field-level definition is an owner collision.

Concrete storage tables may combine or split records for performance, but implemented contracts preserve identity/scope, provenance/anchors, epistemic and lifecycle status, applicable time dimensions, State Fence/policy/config, relations/supersession, privacy/visibility and reconstruction/receipt path.

### Initial executable set

D0/D1 activates only the minimum needed for the operational spine:

```text
Product/WorkScope/Task identity;
State Fence, Authority Epoch and Operation Identity;
TaskContract and ObservationCandidate;
PreparedTransition, OperationState and WriteReceipt;
Instrument/Verification receipts;
Finish attempt/proof/decision;
ProblemState and RecoveryDirective;
Agent response disposition and generated reason-code registry.
```

Later contracts activate when a real consumer/test seam appears. Entries outside the active set remain target/migration vocabulary and are not handed to agents as work merely because they are listed.

