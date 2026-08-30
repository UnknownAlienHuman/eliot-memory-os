## I3.4. Capability and Route Registry

This is the Governor-owned evidence view from I1.9. It is neither the Module Catalog nor the Kernel Generation Registry.

Registry stores evidence-linked facts, not vendor labels and booleans. It separates five identity layers:

```text
host family       — codex, opencode, claude, antigravity, acp-agent, ...;
adapter            — exact ELIOT integration implementation or bundle;
protocol/transport — App Server+stdio, HTTP+SSE, ACP+stdio, sidecar+NDJSON, ...;
runtime instance   — exact executable/package version and hash;
route              — provider/model/auth/billing/feature configuration.
```

Canonical registry shapes:

```yaml
RuntimeInstallation:
  installation_id:
  host_family:
  executable_or_endpoint:
  runtime_version_and_hash:
  os_architecture:
  execution_identity: service | interactive_user | remote
  user_or_service_binding:
  discovered_from:
  status: candidate | enabled | disabled | quarantined

Observed degradation/readiness is held in capability evidence, not in the installation definition.

UserBrokerAuthorization:
  installation_id:
  user_sid:
  allowed_route_classes:
  privacy_and_budget_ceiling:
  consent_and_policy_snapshot:
  status: allowed | suspended | revoked

UserBrokerRegistration:   # Kernel-owned ORS record, not canonical semantic state
  registration_id:
  installation_id_and_user_sid:
  windows_session_id:
  broker_artifact_hash_and_generation:
  broker_epoch:
  pid_job_lineage_and_pipe_identity:
  launch_nonce_and_lease_refs:
  last_heartbeat_and_expiry:
  status: attaching | active | draining | detached | expired | fenced

HostAdapterManifest:
  adapter_id_and_hash:
  protocol_kind:
  transport_kind:
  compatibility_range:
  permissions_network_and_secret_boundary:
  raw_and_normalized_event_contract:
  launch_health_cancel_reconcile_contract:
  supply_chain_and_rollback:

RuntimeRoute:
  route_id:
  adapter_id:
  provider_and_model_request:
  auth_profile_class:
  billing_mode:
  execution_identity: service | interactive_user | remote
  required_user_broker_class:
  reasoning/tool/context serializer fingerprint:
  privacy_classes:
  quota_sources:
  required_capability_profile_ref:
```

`RuntimeRoute` owns configured intent and compatibility only. Current liveness/readiness/capacity is joined from `CapabilityEvidenceRecord` and `DynamicCapabilityPulse`; it is not mutable state inside the route definition.

### Capability evidence

Capability is not a boolean. Every capability claim has:

```yaml
CapabilityEvidenceRecord:
  capability:
  status: declared | probe_passed | observed | degraded | broken | unsupported | unknown
  source: official_contract | runtime_handshake | active_probe |
          production_observation | source_inspection |
          reproduced_failure | imported_legacy_declaration
  scope_fingerprint:
    runtime_hash:
    adapter_hash:
    os_architecture:
    auth_profile_class:
    provider_model_route:
    feature_flags_and_serializer:
  limitations_and_negative_evidence:
  evidence_refs:
  observed_at:
  expires_at:
```

Rules:

```text
legacy bool → declared/imported_legacy, never verified;
broken/unsupported on the exact fingerprint overrides declared;
production admission requires matching probe_passed or observed evidence;
runtime/adapter/provider/serializer change makes dependent evidence stale;
capability may be route/account-specific and cannot be generalized silently;
quarantine is keyed as narrowly as the evidence permits, not by vendor name alone.
```

The following donor-derived shapes are **evidence variants/views under `CapabilityEvidenceRecord`**, not independent capability owners or parallel registries:

```text
ProcessOriginEvidence          — neutral process-attribution observation;
OwnershipChallengeReceipt      — operation-specific ownership challenge;
StaticCapabilityAttestation    — expensive identity/compatibility evidence;
DynamicCapabilityPulse         — current liveness/readiness/capacity evidence;
BehavioralCapabilityChallenge  — harmless negative challenge for one property;
CapabilityOutcome              — scoped degradation/requalification result.
```

They may be persisted as typed evidence records, but current availability and admission are derived only by the Governor-owned Capability Registry view.

### Route fingerprint and actual route

`RouteFingerprint` includes all semantics that can change behavior:

```text
host family and adapter;
protocol/transport;
runtime and adapter hashes;
provider/model/auth/billing;
message serializer/chat template;
tool-call ID and role ordering semantics;
reasoning continuation/compaction behavior;
feature flags and behavior-affecting tool/context profile hashes.
```

The task Policy/Config snapshot, privacy class and budget envelope are referenced by the RoutingReceipt and RunAttempt, not folded into the stable route fingerprint unless they actually change the prompt/tool/serializer behavior. Unrelated policy edits therefore do not invalidate route capability evidence.

Requested route and observed route are stored separately in `ActualRouteReceipt`. If runtime does not expose provider/model/billing evidence, the field is `unknown`, not inferred from UI selection or prompt text.

### Usage and quota

Usage values distinguish:

```text
known;
estimated;
unknown;
not_exposed;
not_applicable.
```

Quota windows may coexist: rolling hours, week, month, credits, premium requests, RPM/concurrency. Every value preserves source, confidence, observed time and reset time. Subscription quota is not converted to dollars without an explicit provider contract.

### Route outcome profile

`RouteOutcomeProfile` is a derived Empirical Profile used by routing, never a capability or proof by itself:

```yaml
RouteOutcomeProfile:
  route_fingerprint:
  task_class_and_recipe:
  governance_and_environment_profile:
  sample_window_and_distribution:
  verified_complete_partial_failed_unknown_counts:
  verifier_coverage_and_quality_measures:
  latency_cost_quota_and_cleanup_measures:
  continuation_context_and_route_mismatch_failures:
  independence_and_common_lineage_notes:
  confidence_coverage_and_known_biases:
  evidence_refs:
  valid_until_and_stale_dependencies:
```

The profile is sparse and conservative. Before enough equal-stack evidence exists, routing uses policy defaults and controlled pilots. A fingerprint, evaluator, task-distribution or behavior-affecting harness change makes the affected profile stale. Aggregated success never authorizes an action or hides minority failures.


### Process origin, capability challenge and readiness evidence

Capability readiness is derived from multiple orthogonal observations, never one boolean, PID, port or cached declaration.

```yaml
ProcessOriginEvidence:
  process_ref_and_pid:
  observed_start_identity_and_exit_or_zombie_state:
  image_and_argv0_artifact_refs:
  managed_tree_and_shared_runtime_refs:
  origin: INSIDE_MANAGED_TREE | SHARED_SUBSTRATE | ELSEWHERE | UNKNOWN
  evidence_refs:
  observed_at_and_freshness:
  valid_for_operation_classes:

CapabilityProbeResult:
  capability_and_generation:
  neutral_observations:
  coverage_and_ambiguity:
  evidence_refs:

OperationDisposition:
  operation_class:
  probe_result_ref:
  decision: ALLOW | ALTERNATE | OBSERVE_ONLY | REQUIRE_AUTHORITY | BLOCK
  policy_rule_and_scope:
  recovery_directive_ref:
```

`ProcessOriginEvidence` is evidence, not authority. The same ambiguous origin may permit read-only status, choose an alternate launch port and still forbid shutdown/mutation. Policy consumes the neutral probe through `OperationDisposition`; probe code does not decide the action.

An ownership claim used for kill, mutation, adoption or credential attachment additionally requires a current `OwnershipChallengeReceipt` binding installation identity, process start identity, generation/epoch and a non-reusable nonce or owner-token challenge. Port occupancy, executable family, PID file or path similarity alone can never authorize control of the process.

```yaml
OwnershipChallengeReceipt:
  installation_and_managed_generation:
  process_ref_pid_and_start_identity:
  image_argv0_and_managed_tree_evidence:
  authority_epoch_and_state_fence:
  challenge_nonce_or_owner_token_hash:
  observed_response_and_checked_at:
  allowed_operation_classes:
  expiry_and_invalidation_set:
```

Critical capabilities combine:

```yaml
StaticCapabilityAttestation:
  artifact_config_protocol_and_dependency_hashes:
  compatibility_claims_and_expensive_probe_receipts:
  invalidation_set:

DynamicCapabilityPulse:
  exact_generation:
  cheap_behavioral_probe:
  observed_at_and_freshness_window:
  liveness_readiness_capacity_and_degradation:
```

Static compatibility without a live pulse is not current readiness. A live `/health` without exact artifact/generation identity is not semantic capability.

`BehavioralCapabilityChallenge` proves one exact property through an intentionally invalid but harmless request and the expected typed failure:

```yaml
BehavioralCapabilityChallenge:
  capability_revision_and_target_generation:
  harmless_invalid_request:
  expected_typed_failure:
  forbidden_effects:
  observed_response:
  result: SUPPORTED | UNSUPPORTED | AMBIGUOUS
  state_fence_and_evidence_refs:
```

Examples include wrong capability token, invalid revision, known-bad verifier artifact and an advertised optional method. A successful challenge never generalizes beyond its exact property/fingerprint.


A capability failure is scoped to the narrowest observed lifecycle. One bad call or item does not silently poison an installation or every future route:

```yaml
CapabilityOutcome:
  capability_and_requested_mode:
  effective_mode:
  degradation_scope: ITEM | CALL | ATTEMPT | SESSION | GENERATION | INSTALLATION
  reason_and_evidence_refs:
  affected_outputs_or_operations:
  proof_ceiling:
  recovery_requalification_or_expiry:
```

Promotion to a broader degradation scope requires evidence that the broader owner or generation is defective. A call-scoped fallback remains visible in the attempt receipt and cannot become a sticky global capability flag. Conversely, a generation-level challenge failure cannot be hidden as one harmless call error.

