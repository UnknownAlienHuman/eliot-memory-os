## I6.15. Capability Grant Lineage, introductions and resource facets

Governor owns canonical grant semantics, parent lineage, policy reconciliation and introduction compilation. Kernel owns activation/revocation enforcement, Authority Epoch fencing and compact snapshots/handles. Adapters and workers can request or present capability evidence but never create a grant or introduction themselves.

Installed capability, authority and presented tool/resource surface are three different states:

```text
Capability Registry
  what exists and is currently healthy/probed;

Capability Grant Lineage
  what a holder is permitted to use/do;

Capability Introduction
  which exact resource facet is presented to one Session/Attempt/component now.
```

Availability never creates authority. Authority does not create an ambient catalog.

### Capability grant lineage

`CapabilityToken` remains a compact transport/projection form. Canonical delegation is represented by an acyclic `CapabilityGrant` lineage:

```yaml
CapabilityGrant:
  grant_id:
  parent_grant_id:             # absent only for an explicit authority root
  authority_root_ref:
  issuer_principal:
  holder_principal_session_attempt_or_component:
  allowed_operations:
  resource_and_effect_set:
  data_and_observation_classes:
  route_and_credential_constraints:
  subtree_depth_fanout_budget:
  state_fence:
  authority_epoch:
  issued_at_expires_at:
  max_uses:
  status: pending_activation | active | narrowed | revoked | expired | stale
  canonical_decision_ref:
  kernel_activation_or_revocation_ref:
```

Rules:

```text
parent relation is acyclic;
each child is an intersection of parent authority, requested scope and current policy;
multiple independent authority paths are separate grants, never a mutable multi-parent row;
each effect cites the exact supporting grant path(s);
restore never reactivates a path or epoch.
```

For the first single-user/single-agent slice with no delegation, the lineage may be represented by one authority-root grant and one derived snapshot; no general graph engine or transitive-revocation service is required. Full parent/descendant traversal becomes active only when a real child delegation, alternate authority path or cross-principal resource introduction exists. The simple representation must migrate losslessly into the same contract later.


`EffectiveCapabilitySnapshot` is a derived view:

```text
path effective = root ∩ grant_1 ... ∩ current policy ∩ State Fence;
holder effective = union of valid independent path-effective sets.
```

Revocation is lazy and reverse-reachable:

```text
revoke/narrow exact edge in Kernel/ORS first;
increment grant-graph revision and affected epochs;
recompute only dependent descendants;
preserve a descendant only if another valid root path covers the exact use;
invalidate snapshots and introductions;
interrupt/fence live agent proxies, WASM handles and effect routes;
reconcile canonical state and retain history.
```

`GrantRevocationPreview` shows affected holders, lost operations/resources, surviving alternate paths and in-flight effects. It is advisory; commit revalidates graph revision.

### Capability introduction

```yaml
CapabilityIntroduction:
  introduction_id:
  holder_session_attempt_or_component:
  supporting_grant_refs:
  resource_handle:
  facet_manifest_ref:
  introduced_operation_set:
  observation_domain_refs:
  credential_binding_ref:
  state_fence_and_authority_epoch:
  registry_and_grant_graph_revisions:
  issued_at_expires_at:
  max_calls_or_budget:
  status: active | suspended | revoked | stale | consumed
  receipt_ref:
```

The Attempt compiler derives the minimal introduction set from:

```text
WorkItem + RoleProfile + current grants + privacy/cost policy
+ Capability Registry evidence + State Fence.
```

The introduction set is compiled once per Attempt/root revision and reused until its grant, registry, policy, credential or State Fence dependency changes; it is not a per-call ceremony.

Unintroduced resources are absent even when an adapter is globally installed. A missing exact resource facet returns `CAPABILITY_INTRODUCTION_REQUIRED`; a revoked or stale supporting grant returns `CAPABILITY_GRANT_REVOKED`. Neither condition is translated into a generic tool failure or silently widened introduction.

### Facet manifest

A facet is a stable, narrow, typed interface over a semantic resource:

```yaml
FacetManifest:
  facet_id_and_semver:
  semantic_resource_kind:
  interface_schema_or_WIT_digest:
  implementation_compatibility_range:
  methods:
    - method_id:
      input_output_schema_digest:
      authority_class:
      effect_class:
      observation_class:
      disclosure_propagation:
      idempotency_class:
      simulation_class:
      compensation_class:
      replay_class:
      timeout_and_resource_profile:
  collision_and_reserved_name_policy:
  removal_and_migration_boundary:
```

Every method admitted to an agent/component/public capability surface requires an exhaustive method profile generated from the owning contract. A new unclassified method cannot be exported on that surface. Internal methods and quarantined legacy compatibility routes are not forced into a mass classification campaign merely because they exist; they remain unavailable until a real consumer/migration slice admits them. Contract tooling compares the admitted Rust traits, WIT worlds, EBP registry, MCP schemas and generated role surfaces.

Agent, WASM and native contours use the same semantic facet:

```text
agent route
  → short task-shaped method projection + exact handles;

WASM component
  → stable WIT resource interface + runtime-introduced handles;

native worker
  → EBP proxy/stub generated from the same facet contract.
```

Stable facet families are reused; ELIOT does not generate a unique WIT world per task when dynamic resource handles suffice.

### Principal-bound credential use

```yaml
CredentialUseBinding:
  binding_id:
  resource_and_facet:
  acting_principal:
  credential_owner_principal:
  mode: self_owned | service_owned | explicit_delegation | human_escrow
  allowed_operations_and_data_classes:
  billing_and_retention_route:
  state_fence_and_expiry:
  revocation_ref:
```

A child does not inherit controller credentials by role. Explicit delegation creates a grant and introduction receipt; the actual acting account appears in effect/usage receipts.

An agent may request a missing introduction, but the request is only a candidate:

```text
requested resource/property;
requested facet/operations;
why the current set is insufficient;
expected decision/proof delta;
privacy, cost and effect implications.
```

The result is introduced, denied, needs Human/resource selection, safer-facet required, route unavailable or probe through an existing capability.

No new authority owner is created by these contracts. Governor decides semantic admission; Kernel enforces current grant/introduction/epoch snapshots; adapter/component only implements the facet.



### Native resource leases and executable dependency closure

A service/worker does not receive ambient file-system authority merely because a Human selected a path. `NativeResourceLease` is required when a resource crosses a user/service, trusted/untrusted-module or external-worker boundary, and for Material/Critical use whose identity may change between selection and execution. Ordinary reads and edits inside an already authenticated WorkScope/worktree root use the bounded WorkLease/Facet capability and do **not** create one lease per file. User Broker or another authorized issuer creates a one-shot operation-bound lease only for the exact boundary-crossing operation:

```yaml
NativeResourceLease:
  lease_id_and_nonce:
  issuer_broker_epoch_and_consumer_generation:
  principal_attempt_and_operation:
  opaque_resource_ref:
  canonical_resource_identity:
  resource_kind_and_reparse_network_device_policy:
  size_mtime_or_directory_generation:
  issued_at_expires_at:
  state_fence:
  signature_or_protected_issuer_identity:
  consumed_at_and_receipt:
```

Immediately before use, the consumer re-resolves and remeasures the resource identity. Replay, operation mismatch, stale broker epoch, symlink/reparse substitution, changed file identity or expired lease fails closed for the dependent operation. Signing secrets never enter the child environment. Agents see an opaque `ResourceRef`, not a broad reusable path grant.

Consent/approval applies to the full executable dependency closure, not a package label. The closure is computed and cached per immutable artifact/build generation; it is revalidated on dependency/config/toolchain change, not rebuilt ceremonially for every attempt:

```yaml
ExecutableDependencyClosure:
  root_artifact:
  executable_code_dependencies:
  data_with_execution_semantics:
  build_macro_template_deserialization_and_plugin_surfaces:
  combined_fingerprint:
  scanner_policy_and_containment_revision:
  approved_by_scope_and_expiry:
  hard_block_and_approvable_findings:
  invalidation_set:
```

Execution classes remain distinct:

```text
native code;
deserialization/pickle-like execution;
build script and procedural macro;
template/macro execution;
plugin/model loading;
model/tool-generated command execution.
```

A static scanner is hardening and triage, not a sandbox or semantic oracle. The applicable containment, negative challenge, runtime identity and verifier remain mandatory. Approval of one artifact does not transitively approve its changed tokenizer, base model, adapter, plugin or build dependency.

