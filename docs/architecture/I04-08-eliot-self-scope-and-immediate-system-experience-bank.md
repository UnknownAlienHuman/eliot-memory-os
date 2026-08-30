## I4.8. ELIOT self-scope and immediate system-experience bank

`kind = eliot_system` binds:

```text
accepted Architecture revision;
Implementation revision;
Module Catalog, Generation Registry and Capability Registry views;
conformance map;
current builds;
operational health;
incidents and improvement candidates.
```

Every ELIOT component emits observations about its own operation at the boundary where they become observable. This is implemented as two related but distinct stores so that “record everything” does not turn Cognitive Inheritance into a log dump. The Governor-owned operational/audit admission path owns `SystemObservationJournal`; Canonical Memory owns only the admitted `eliot_system` experience records. Watchdog, Dreamer, Doctor, agents and Modules are producers, not alternate writers:

```text
SystemObservationJournal
  append-only operational/audit events for every normalized observation,
  with exact raw/log/blob handles, retention and coverage gaps;

EliotSystemExperienceBank
  canonical self-scope ObservationCandidates/episodes/failures/outcomes derived from
  material or recurring journal events, with provenance and no automatic truth/policy status.
```

These are logical stores with different authority and retention, not a requirement for two database products. `SystemObservationJournal` is the Governor-owned durable-audit family behind `CanonicalStoreService` (or a compatible append-only audit segment through the same store bridge); raw high-volume bodies live in BlobStore/operational logs by handle. `EliotSystemExperienceBank` is the only semantic self-memory. Neither Watchdog spool nor operational logs can answer semantic queries or promote records without Governor reconciliation.

Before an active interval begins, Governor/Kernel compile an `ActiveObservationPlan` from versioned producer obligations and actual integration capability. The owner of each Module/route contract declares its `ObservationObligationProfile`; Governor owns the admitted profile catalogue and plan compilation; Watchdog independently challenges observed coverage; no producer can self-certify that its own silence means healthy operation:

```yaml
ObservationObligationProfile:
  producer_capability_and_generation:
  applicable_activation_session_task_or_job_classes:
  expected_event_classes_and_trigger_boundaries:
  required_capture_route_and_minimum_durability:
  denominator_source_and_expected_count_or_interval:
  allowed_sampling_coalescing_and_raw_handle_policy:
  maximum_blind_interval_and_freshness:
  failure_gap_and_governance_disposition:
  invalidation_set:

ActiveObservationPlan:
  activation_and_governance_profile:
  admitted_obligation_profile_refs:
  observable_and_unobservable_sources:
  expected_denominators_and_cursor_ranges:
  protected_event_classes:
  known_blind_intervals:
  expiry_and_recompile_triggers:
```

Silence is evidence of absence only when the corresponding obligation, denominator and observation interval were known and complete. Otherwise ELIOT records `INCOMPLETE_COVERAGE`, `UNAVAILABLE` or `UNKNOWN`; it never invents a missing observation after the run. New Module/route generations cannot claim full supervision until their observation obligations are registered and challenged.

```yaml
EliotSystemObservationEvent:
  event_id_and_time:
  producer_generation_and_trace:
  kind: agent_feedback | context_packet | memory_delivery | tool_or_route |
        task_progress | loop_or_no_progress | failure_or_repair | queue_resource |
        configuration | maintenance | security | product_outcome | user_correction
  affected_scope_task_attempt_module_or_route:
  observed_delta_and_expected_baseline:
  evidence_and_raw_handles:
  coverage_and_blind_intervals:
  privacy_retention_and_disclosure:
  candidate_importance_and_dedup_key:
```

The minimal event or an explicit telemetry-gap record is persisted before the observer reports success. If canonical self-scope admission is unavailable, Watchdog spool/ORS-outbox preserves the event identity for reconciliation. High-volume raw telemetry remains in operational logs/BlobStore; Dreamer/Meta receives bounded aggregates and exact handles. Promotion to a FailureFingerprint, procedure, policy or ImprovementCandidate requires the normal governed path and outcome evidence.

“Every observation” means every admitted observation transition or explicit coverage gap, not every high-frequency metric sample or raw log line. Sensors may aggregate samples before journal admission only under a versioned aggregation/coverage rule that preserves min/max/count/time range and raw evidence handles.

Self-observation is bounded rather than lossy-by-convenience. Repeated low-value events may be coalesced behind one count/time-range record and raw handle; critical state transitions, feedback, unknown effects and coverage gaps are never replaced by a success counter. Queue pressure creates an explicit `self_observation_gap` Watchdog/audit coverage record through protected capacity and lowers the applicable Governance Profile. The journal itself cannot block unrelated product work unless the missing observation crosses a declared Hard Boundary.

Self-observation is explicitly non-recursive. Admission, coalescing, import and read of a `SystemObservationJournal` event do not emit another ordinary journal event about themselves. Only a change of journal health, coverage, persistence or reconciliation state emits one separately keyed control event. Feedback about a feedback request follows the same rule. This prevents infinite “observation of observation” chains and false activity.

Durability is proportional to the guarantee being claimed:

```text
critical authority/effect/security/finish/coverage transition
  → durable journal/audit or protected gap record before success is returned;

ordinary diagnostic/performance/utility observation
  → durable bounded outbox enqueue before the producer forgets it;
  → semantic import may be asynchronous;

high-rate sample
  → versioned aggregate plus raw evidence handle and coverage interval.
```

Failure of the ordinary Meta import path does not sabotage unrelated product work. It creates a visible coverage gap and degrades only guarantees that depended on that observation. Failure of the protected path blocks only the exact transition whose auditability is a Hard Boundary.

Before a Material change to ELIOT, the self-scope compiler adds applicable `ARCH-*`, Implementation sections, current conformance gaps, recent system-experience evidence and open improvement/recovery obligations. Ordinary project packets do not inherit the self-scope journal or maintenance history by default; only an active system directive, route/tool limitation or admitted system lesson that changes the current task may cross that boundary, with an exact handle and influence receipt.

---

