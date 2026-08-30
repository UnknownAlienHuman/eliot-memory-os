## I14.29. Stage-local recovery, progress clocks and parkable resources

Durable pipelines recover at independently verifiable causal stages, not at arbitrary process or whole-task boundaries.

```yaml
StageRecoveryReceipt:
  durable_job_attempt_and_pipeline_revision:
  last_verified_prefix:
  preserved_stage_outputs_and_receipts:
  interrupted_stage:
  invalidated_partial_outputs:
  downstream_suffix_invalidated:
  new_attempt_ref:
  state_fence_before_after:
  cleanup_evidence:
  unresolved_external_effects:
```

Resume preserves the verified prefix, clears or quarantines the interrupted suffix and repeats only the smallest causal stage whose effect/outcome is not proven. A partial artifact never becomes a finished stage because its process exited cleanly or bytes exist.

Every long operation uses independent progress clocks:

```yaml
ProgressClockSet:
  admitted_at:
  process_started_at:
  first_transport_output_at:
  first_semantic_delta_at:
  last_transport_heartbeat_at:
  last_semantic_delta_at:
  current_stage_started_at:
  stage_deadline:
  semantic_idle_deadline:
  total_deadline:
  cleanup_deadline:
  progress_evidence_refs:
```

Queue keepalive, TCP/SSE heartbeat and output bytes prove transport liveness only. Semantic progress requires a new accepted artifact, evidence delta, stage transition, resolved finding or other task-specific observable.

A logical Attempt may park a scarce physical resource without losing identity:

```yaml
ParkableResourceSublease:
  parent_attempt_and_resource_class:
  physical_lease_and_generation:
  parked_at_reason_and_checkpoint:
  resources_released_and_resources_still_held:
  reacquire_priority_and_budget:
  expiry_cancellation_and_fairness_policy:
  reacquire_receipt_or_failure:
```

Examples include GPU inference waiting for Human tool approval or an agent execution slot waiting for merge authority. Parking does not retain hidden GPU/process capacity, does not bypass the queue and does not guarantee reacquisition. Cancellation while parked is terminal unless a new attempt is admitted.

Pipelines that can consume all currently free capacity reserve downstream headroom explicitly:

```yaml
DownstreamHeadroomReservation:
  pipeline_stage_and_consumer:
  transient_resource_formula_or_empirical_profile:
  CPU_memory_GPU_disk_network_context_model_and_queue_reservations:
  uncertainty_and_overcommit_policy:
  release_condition:
  measured_peak_and_reconciliation:
```

This reservation is separate from Kernel Control Reserve. It protects product completion of the admitted pipeline—for example reduction, verification, export or response generation—without granting the stage authority over system recovery capacity.

`ResolvedExecutionReceipt` records actual execution rather than the configured label:

```yaml
ResolvedExecutionReceipt:
  requested_route_resource_and_revision:
  resolved_provider_model_repo_and_revision:
  actual_runtime_and_artifact_hashes:
  tokenizer_template_processor_and_adapter_refs:
  device_precision_quantization_and_load_mode:
  fallback_or_remap_chain:
  resource_attestation_status: ATTESTED | INCOMPLETE | UNKNOWN
  compatibility_profile_and_state_fence:
  evidence_refs_and_reason_if_unattested:
```

Fallback is classified before continuation:

```text
same semantics + same State Fence
  → same attempt may retry;

same objective but different route/resource/tool/context semantics
  → new attempt with sealed handoff and new receipts;

equivalence cannot be established
  → UNKNOWN / DEGRADED / BLOCKED;

exact requested identity unavailable
  → never substitute latest/default silently.
```

A materially different fallback is not a successful execution under the original label.

Ownership clarification:

```text
ProgressClockSet
  → fields/projection of the owning DurableJob or AgentAttempt;

StageRecoveryReceipt
  → typed Recovery/Checkpoint receipt under the existing recovery owner;

ParkableResourceSublease
  → specialization/revision of the existing Resource Lease family;

ResolvedExecutionReceipt
  → shared actual-execution payload embedded by PhysicalModelAttemptReceipt,
    InstrumentRun or ML-worker receipt; not a parallel generic receipt owner.
```

These shapes improve observation and recovery without creating new task, authority, lease or receipt roots.

