## I7.23. Raw and normalized host events

Every native event is stored as:

```text
immutable raw payload/blob + hash;
normalized HostEventEnvelope;
adapter and transformation versions;
sequence/event/cursor and parent-child lineage;
normalization loss/warnings;
requested/actual route and usage references.
```

Normalized event is used for policy, state and UI. Raw payload is used for forensic replay and parser correction **only within the applicable retention/privacy contract**. Secret values, provider-forbidden hidden reasoning and data outside the WorkScope privacy boundary are never persisted merely to preserve “rawness”. The ingest path stores an exact transport hash plus either the allowed raw bytes or a deterministic redacted representation with a redaction receipt. Cursor advancement is published only after the admissible raw/hash record and normalized projection are durably related and the EventEnvelope disposition is recorded. Reconnect replays unacknowledged durable events by stream cursor; duplicates are idempotent.

Logical turn state, process state and native event cursor are distinct. A live process may be idle/orphaned; a native `completed` status may still map to ELIOT `PARTIAL`, `FAILED_VERIFICATION` or `UNKNOWN_OUTCOME`.

Structured usage records preserve root/child/aggregate scope and `known | estimated | unknown | not_exposed | not_applicable`. Zero is never used as a substitute for missing data.

For evaluations and policy claims, ELIOT derives a `HostObservedComplianceTrace` from immutable host/runtime events rather than model prose:

```text
allowed Tool/Facet manifest digest;
observed tool calls and non-tool actions;
filesystem/repository/shell/web access;
artifact writes and external effects;
raw-event/cursor coverage and blind intervals;
PASS | TAINTED | FAIL disposition.
```

A run advertised as ELIOT-only loses compliance comparability when it reads hidden schema/output files, uses undeclared shell/web access or writes outside its namespace. Missing host coverage is `TAINTED/UNKNOWN`, never a self-reported PASS.

Any claim about observed compliance, event completeness, hook enforcement or route behavior also binds a versioned denominator:

```yaml
ObservationCoverageManifest:
  product_session_attempt_and_route_fingerprint:
  expected_event_sources_and_event_classes:
  observable_and_unobservable_actions:
  first_and_last_expected_cursors_by_stream:
  received_applied_rejected_and_unknown_counts:
  sequence_gaps_duplicates_reorders_and_payload_mutations:
  blind_intervals_and_missing_source_reasons:
  coverage_by_material_action_and_effect_route:
  denominator_origin_and_sampling_policy:
  completeness: COMPLETE | PARTIAL | UNKNOWN | NOT_APPLICABLE
  proof_ceiling_and_invalidation:
```

An absent event is evidence of non-occurrence only when the applicable source/class is in the denominator, its cursor interval is complete and no blind interval covers the action. Otherwise the result is `UNKNOWN/PARTIAL`; coverage percentages without a declared denominator are invalid. Gap, duplicate, reorder, payload-mutation and cross-scope replay faults are part of the host-event conformance suite.

