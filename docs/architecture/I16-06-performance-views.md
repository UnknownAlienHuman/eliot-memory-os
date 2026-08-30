## I16.6. Performance views

Separate:

```text
prefill/TTFT vs decode;
cold vs warm;
p50 vs p95/p99 under contention;
normal latency vs time-to-safe-recovery;
nominal cost vs retry/replay/compaction;
module start vs steady state.
```

No single performance score.

Every canonical-write latency claim is decomposed before protocol or process optimization:

```yaml
CanonicalWriteLatencyProfile:
  exact_product_machine_storage_and_contention_profile:
  payload_bytes_and_encoding:
  bridge_to_kernel_serialization_and_IPC:
  kernel_to_daemon_serialization_and_IPC:
  validation_admission_and_reservation:
  ORS_stage_and_durability:
  daemon_to_store_bridge_serialization_and_IPC:
  store_bridge_to_database_transport:
  database_commit_and_durability:
  receipt_return_ORS_reconciliation_and_outbox:
  p50_p95_p99_max_and_sample_count:
  CPU_allocations_IO_fsync_and_queue_wait:
  bottleneck_and_candidate_change:
```

JSON-first EBP remains a D0/D1 Default until measured boundary cost makes an alternative materially useful. A paper estimate cannot promote Protobuf or remove a process boundary; an observed bottleneck opens the protocol/placement experiment with semantic-equivalence and recovery tests.

Every published performance/capacity claim is a versioned `CapacityEnvelope`:

```yaml
CapacityEnvelope:
  product_and_runtime_identity:
  hardware_os_storage_and_network_fingerprint:
  corpus/storage tier and data shape:
  workload/task/profile and route fingerprint:
  concurrency, queue/backlog and reserve configuration:
  sample count, warmup and error/uncertainty method:
  p50_p95_p99_max and saturation point:
  CPU_RSS_handles_IO_WAL_device-write metrics:
  crash_restart_recovery_backup_restore timings:
  semantic equality/proof ceiling:
  validity, expiry and invalidation conditions:
```

`n=1` is an observation, never percentile evidence. Capacity measured on the old testbed or one small corpus is not inherited by the target runtime.

Corpus scale is represented by a versioned profile rather than universal byte tiers:

```yaml
CorpusScaleProfile:
  profile_id_and_scope:
  source_classes_and_privacy_domains:
  canonical_record_blob_and_index_bytes:
  record_episode_document_log_and_artifact_counts:
  graph_nodes_edges_and_projection_generations:
  history_window_and_active_archive_ratio:
  query_ingest_compaction_backup_and_restore_workloads:
  expected_growth_and_retention:
  applicable_capacity_envelope_refs:
  qualification_uncertainty_expiry_and_kill_condition:
```

A capacity result transfers only to a compatible CorpusScaleProfile. External research, foreign-code or bulk-log use is not product-admitted from a small development corpus merely because the same query succeeds.

