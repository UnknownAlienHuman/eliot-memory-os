## I7.20. Agent-facing error contract

Agent-facing failure control has two layers:

```text
AgentResponseDisposition (small closed control enum):
  INVALID_REQUEST | DENIED | STALE_OR_CONFLICT | NEEDS_EVIDENCE |
  UNAVAILABLE_OR_CAPACITY | RECOVERY_REQUIRED | FAILED;

reason_code (open versioned registry):
  exact machine-readable cause from Appendix D.
```

Appendix D and `docs/generated/reason-codes.md` are the current human/machine-readable documentation projections of the additive reason-code set, not a giant control-state enum that every bridge or agent must understand. I7.20 owns the exact current documentation set; a future generated runtime registry must match it. Until exact runtime source and execution evidence exists, the projected registry remains `ImplementationSupport = TARGET` with `EvidenceExecutionStatus = NOT_EXECUTED`. Bridge-only legacy aliases remain separate. Unknown future reason codes are preserved verbatim and handled through the stable disposition and typed directive; they do not break decoding or silently become success. Aliases are accepted only at migration/compatibility boundaries and are not members of the current reason catalogue. Agent surfaces group reasons without changing their exact identity:

```text
request/identity     — INVALID_ARGUMENT, AUTHENTICATION_REQUIRED, WORKSCOPE_UNAUTHENTICATED,
                       SCAN_PRIVACY_BOUNDARY_REQUIRED, IDENTITY_CONFLICT, TASK_SELECTION_REQUIRED,
                       TASK_SCOPE_INCOMPATIBLE, DISPATCH_PERMIT_REQUIRED, DRY_RUN_UNSUPPORTED,
                       PROCESS_OWNERSHIP_UNPROVEN, RESOURCE_LEASE_REQUIRED,
                       RESOURCE_IDENTITY_CHANGED, RESOURCE_LEASE_REPLAYED;
authority/policy     — AUTHORITY_REQUIRED, POLICY_DENIED, ACTION_LEASE_REQUIRED,
                       WRITESET_VIOLATION, IMPACT_ESCALATION_REQUIRED;
state/conflict       — STALE_STATE_FENCE, STALE_AUTHORITY_EPOCH, STALE_PROJECTION, OBSERVATION_GAP,
                       SCOPE_CONFLICT, CONFLICT_OPEN, CRITICAL_ATTENTION_OPEN, SEQUENCE_GAP_OPEN, TRANSITION_DIGEST_MISMATCH,
                       AMBIGUOUS_RESULT, DESCENDANT_CLOSURE_INCOMPLETE;
cognition/proof      — NEEDS_REASONING_CANDIDATE, CUE_BINDING_REQUIRED,
                       PACKET_REFRESH_REQUIRED, PROBE_REQUIRED, NOT_ONBOARDED,
                       CAPSULE_STALE, VERIFIER_REQUIRED, VERIFIER_STALE, VERIFICATION_NOT_EXECUTED,
                       LEGACY_FINISH_INPUT_REJECTED, DECISION_CONTEXT_INCOMPLETE,
                       CONTEXT_PROFILE_UNVALIDATED, TRACE_INCOMPLETE,
                       REFERENCE_NOT_ALLOWED, UNSUPPORTED_PRECISION;
route/integration    — CAPABILITY_UNVERIFIED, CAPABILITY_DEGRADED,
                       CAPABILITY_UNAVAILABLE, SUPERVISION_UNAVAILABLE, CAPABILITY_GRANT_REVOKED,
                       CAPABILITY_INTRODUCTION_REQUIRED, ROUTE_UNAVAILABLE, ROUTE_MISMATCH,
                       RESEARCH_SOURCE_UNAVAILABLE, EXTERNAL_ATTACH_RECONCILIATION_REQUIRED,
                       ADAPTER_UNAVAILABLE, ADAPTER_INCOMPATIBLE, RUNTIME_FAILED,
                       CANCELLATION_UNCONFIRMED, ENVIRONMENT_UNAVAILABLE,
                       PROTOCOL_INCOMPATIBLE, NO_PROGRESS,
                       TRANSLATION_LOSS_FORBIDDEN, STREAM_SEMANTIC_ORDER_VIOLATION,
                       MODEL_ATTEMPT_UNKNOWN_OUTCOME;
instrument/evidence  — INSTRUMENT_UNAVAILABLE, INSTRUMENT_FAILED,
                       INSTRUMENT_PARSER_INCOMPATIBLE,
                       INSTRUMENT_EVIDENCE_INCOMPLETE,
                       INSTRUMENT_OUTPUT_TRUNCATED,
                       PROCESS_TREE_CLEANUP_FAILED,
                       TESTD_UNAVAILABLE, TESTD_JOB_FAILED,
                       BUILD_SANDBOX_UNPROVEN,
                       COMPONENT_INTERFACE_INCOMPATIBLE,
                       COMPONENT_CAPABILITY_DENIED, COMPONENT_TRAP,
                       COMPONENT_DIVERGENCE, COMPONENT_MIGRATION_REQUIRED,
                       SIMULATION_REPLAY_MISMATCH,
                       GENERATION_PROMOTION_BLOCKED,
                       NEGATIVE_RESULT_UNPROVEN, EVIDENCE_STALE,
                       EVIDENCE_COVERAGE_PARTIAL;
testing              — TEST_INVENTORY_STALE, TEST_POLICY_INCOMPLETE;
capacity/availability— BUSY, STATE_CHURN, DEADLINE_EXCEEDED, STORAGE_BACKPRESSURE,
                       ACCEPTED_PENDING, DB_UNAVAILABLE, DEFERRED_CAPACITY,
                       PROVIDER_QUOTA, BUDGET_EXHAUSTED, MODULE_QUARANTINED;
security/recovery    — PRIVACY_DENIED, DISCLOSURE_CLOSURE_INCOMPLETE,
                       OMITTED_SOURCE_UNAVAILABLE, SOURCE_QUARANTINED, ORIGIN_AUTHENTICATION_FAILED,
                       EXECUTABLE_DEPENDENCY_UNAPPROVED, MIGRATION_MAPPING_INCOMPLETE, UNKNOWN_COMMIT,
                       UNKNOWN_OUTCOME, RECOVERY_REQUIRED, RECOVERY_LOCK_UNAVAILABLE,
                       CUTOVER_BLOCKED_INFLIGHT_EFFECT, INCIDENT_LOCKDOWN.
```

Every non-success response includes `disposition`, exact `reason_code`, the applicable Recovery or Conflict Directive and the same operation identity when one exists. Bridges switch on the stable disposition and MAY specialize known reason codes; they may not require an exhaustive compile-time match over the entire additive reason registry. Legacy names translate only through the bridge-alias mapping projected in `docs/generated/reason-codes.md` and never create host-specific semantic control enums. Silence, raw deserialization output and generic internal-error prose are not normal control behavior.

