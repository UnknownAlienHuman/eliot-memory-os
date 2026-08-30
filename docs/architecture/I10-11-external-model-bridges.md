## I10.11. External model bridges

Each provider/model adapter:

```text
receives bounded model-neutral job;
translates tools/messages under a versioned serializer contract;
reports requested and observed route separately;
reports structured usage/quota/cost with source and missing-data state;
preserves required reasoning/tool continuation semantics for that fingerprint;
obeys data/privacy policy;
returns candidate artifact, raw native events and provider receipt;
can be disabled, quarantined or replaced independently.
```

A model ID is not a route identity. Harness, serializer, auth/billing surface, reasoning mode and continuation behavior are part of `RouteFingerprint`.

### DeepSeek/OpenCode Go candidate route

`DeepSeek V4 Flash` through OpenCode Go is an **Empirical Route Profile**, not a capability inferred from the checkpoint name. Admission requires RGF-AGENT-ROUTES and an exact fingerprint covering provider endpoint, OpenCode/runtime version, serializer/chat template, tool-role ordering, reasoning mode, reasoning-continuation preservation, compaction and auth/quota surface.

Mandatory pilot probes:

```text
multi-turn tool call → tool result → continued reasoning/tool call;
reasoning/assistant continuation survives the host serializer as required by the route;
actual provider/model and missing fields are reported honestly;
context/output limits and compaction are measured rather than inferred from advertised capacity;
quota/reset/usage are sourced and never treated as zero when unavailable;
controlled implementation tasks are compared with an equal-stack fallback route.
```

Until the pilot demonstrates architecture/planning and verification quality, the route is eligible mainly for bounded implementation, read-only scouting and broad inexpensive coverage. It does not become sole Task Controller, Architecture authority or independent verifier by price or advertised context size.


### Provider protocol translation and physical model-attempt boundary

Provider protocol conversion is a replaceable bridge capability, not a property of canonical memory. ELIOT owns a provider-neutral runtime IR and never re-exports an upstream project's decision or session types as domain contracts.

```yaml
ProviderPayloadHandle:
  artifact_digest_and_wire_format:
  privacy_disclosure_and_retention:
  producer_route_and_generation:
  exact_raw_or_deterministically_redacted_representation:

TranslationPolicyProfile:
  profile: EXPLORATORY | AGENT_TOOLING | PROOF_BEARING | SAME_FORMAT_EXACT
  unknown_field_policy:
  lossy_conversion_policy:
  identifier_policy:
  preservation_policy:
  target_capability_requirements:

TranslationReceipt:
  source_and_target_wire_formats:
  codec_and_policy_revisions:
  source_normalized_and_target_digests:
  diagnostics_refs:
  loss_class:
  event_order_changes:
  synthetic_reconstruction:
  exact_replay_used:
  preservation_generation_and_invalidated_by_mutation:
  omission_and_recovery_handles:
```

A normalized mutation automatically invalidates exact preserved replay. Convenience APIs that discard diagnostics are forbidden on load-bearing paths. Buffered↔stream conversion, tool-argument repair, unknown-block dropping, output-index collapse and event reordering are explicit transformations with proof ceilings.

Large provider inputs are immutable content-addressed bundles or shared read-only buffers plus a small target-specific overlay; adapters do not deep-clone a 100k+ context tree for every classifier, retry or fallback. Raw payload remains behind `ProviderPayloadHandle`, and every derived target representation is linked by `TranslationReceipt`.

Within one provider event boundary, reasoning/thinking deltas precede visible answer deltas unless the source protocol explicitly defines otherwise. Once visible answer content begins, a translator may not silently reopen reasoning. Cross-format ordering is covered by differential/property/fuzz tests.

Routing and execution are separate. `ModelAttemptRole` is a typed enum (`CLASSIFIER | JUDGE | ANSWER | RETRY | FALLBACK | AUDIT | TOKEN_COUNT | SHADOW`) and is never encoded only in free-text rationale.

```yaml
RoutingContextBundle:
  decision_turn:
  goal_and_acceptance_revisions:
  current_query_or_work_unit_handle:
  operational_signals_and_required_capabilities:
  privacy_budget_and_state_fence:
  admitted_background_evidence_handles:
  context_recipe_and_compiler_revision:

ModelCallIntent:
  logical_decision_ref:
  attempt_role: ModelAttemptRole
  routing_context_bundle_ref:
  provider_neutral_input_bundle:
  introduced_tools_and_semantics:
  requested_route_and_deadlines:
  privacy_cost_authority_and_state_fence:

PhysicalModelAttemptReceipt:
  attempt_and_logical_decision_ids:
  requested_and_observed_route_fingerprints:
  request_digest_and_translation_receipt:
  start_first_byte_first_semantic_and_terminal_times:
  cancellation_and_unknown_outcome_disposition:
  provider_status_usage_and_cost:
  safe_public_error:
  restricted_raw_error_artifact:
```

The existing `RoutingReceipt` is the single canonical logical route-decision receipt (the Switchyard research calls the same role `LogicalRouteDecisionReceipt`). It records:

```yaml
RoutingReceipt:
  decision_id_and_decision_turn:
  route_assessment_candidate_ref:
  requested_route_and_selected_route:
  considered_alternatives_and_dispositions:
  decision_source: SIGNAL | JUDGE | ABSTAIN | TIMEOUT | INVALID | DEFAULT | MANUAL | CONTEXT_FALLBACK | PROVIDER_FALLBACK
  privacy_and_cost_admission:
  policy_context_recipe_and_compiler_revisions:
  state_fence:
  pinned_until_boundary:
  evidence_and_uncertainty_refs:
```

A mid-turn fallback cannot silently change tool, reasoning, privacy or billing semantics. The logical receipt never proves that a provider call occurred; that belongs only to `PhysicalModelAttemptReceipt`.

Route policy may use a model-generated `RouteAssessmentCandidate`, but deterministic policy performs admission. Magnitude of a classifier score is not calibrated confidence. A scoped `RouteFailureFingerprint` records route, task/context shape, decision turn, failure class, evidence, expiry and revalidation; it must not quarantine an entire vendor when the failure is narrower.

A classifier/judge is a separate bounded physical attempt with its own deadline, cost quota, reference manifest and failure disposition. Timeout, invalid schema or abstention yields a typed degraded/default decision; it does not masquerade as model certainty. Every static policy branch and fallback tier participates in a reachability check so a dead branch or permanently shadowed route is reported before canary.

### Provider transport hardening

Every privileged provider transport declares and proves:

```text
connect, TLS/headers, first-byte, semantic-idle, overall-job and cleanup deadlines;
retryable conditions, bounded attempt count, exponential backoff with jitter and Retry-After cap;
header allowlist and explicit privacy admission;
bounded request/response/error/event bodies;
safe public error plus restricted raw error artifact;
cancellation and terminal reconciliation;
authenticated loopback/IPC default for local servers;
no synchronous routing-log I/O on the hot path;
no exclusive route/session/state lock across provider/model/network wait.
```

Stateful routing uses snapshot → release lock → external call → reacquire → revision/fence validation. Process-local session affinity is an optimization only and never task continuity or authority. TTL/cleanup/affinity maintenance runs as a supervised bounded job with health, cancellation and observable eviction policy; detached cleanup tasks and arbitrary hash-map eviction are not production lifecycle mechanisms. Invalid, timed-out or abstaining route assessments produce a typed decision source and the declared deterministic baseline/fallback; they are never converted into fabricated classifier confidence.

### Switchyard adoption boundary

A pinned Switchyard `protocol + translation` snapshot MAY be tested behind an ELIOT facade. The first experiment is a representative request/response/stream conformance corpus on Windows with diagnostics preservation, loss accounting, allocation/cost measurement and maintenance review. Stage Router, LLM classifier and whole server remain effect-free shadow candidates until an equal-stack Product Pulse shows material benefit. Switchyard's server, transport, session state and skill store never become ELIOT control owners.

### Optional Unsloth/local-ML execution contours

Unsloth Core/Zoo is an optional pinned ML execution dependency behind ELIOT-owned process bridges. It is not linked into Kernel/Governor, does not receive canonical-store credentials and does not own task, memory, route, budget, evidence or finish state.

The default physical split is:

```text
training worker generation;
clean export/quantization/calibration worker generation;
inference/local-subagent worker generation;
optional Researcher-provider/RAG worker generation.
```

Modes that require incompatible global Python imports, patches, compiler state or device libraries use clean process generations rather than a mutable “toggle” in one giant daemon. Shared model/download CAS is allowed; interpreter/module state is not silently transferred.

Every ML run binds:

```text
exact base/adaptor/model repository and revisions;
tokenizer/template/processor revisions;
dataset manifest, lineage, licenses and privacy;
Torch/Transformers/TRL/PEFT/Unsloth/Zoo/CUDA/driver/runtime fingerprints;
actual device, precision, quantization, load mode and resource profile;
requested-versus-resolved execution receipt;
checkpoint/export/evaluator identities;
cancellation, recovery, cleanup and artifact receipts.
```

A small local model may serve bounded repetitive implementation/scouting or a measured specialist. It cannot become Architecture authority, Current Epistemic Position, permission, general verifier or sole Task Controller. Parametric learning may target narrow replaceable capabilities such as classification/reranking/normalization; user goals, Architecture, authority, privacy, active commitments and current epistemic state remain external governed records.

Admission requires RGF-AGENT-ROUTES and a matched product/control evaluation on this Windows installation. Studio/Desktop, its product database/UI/control plane and “last prose message = result” are not adopted.


### Measurement-path identity

Every benchmark, route comparison and transport/performance claim binds the exact path that was actually measured:

```yaml
MeasurementPathIdentity:
  source_and_build_identity:
  executable_module_and_generation:
  invoked public method_or_handler:
  adapter_codec_and_profile revisions:
  runtime_route_and_environment:
  candidate_or_legacy_path discriminator:
  raw execution_receipt_refs:
```

A benchmark of a legacy Python path, synthetic service, alternate handler or unobserved fallback cannot be attributed to the current Rust/native production path. Missing path identity narrows the claim to `UNVERIFIED_PATH` rather than borrowing the product label.

