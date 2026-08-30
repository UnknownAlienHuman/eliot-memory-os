## I5.6. Admission and staging

```text
1. authenticate principal/session;
2. validate schema, envelope, size and canonical request identity;
3. resolve authenticated WorkScope, scope level and Ordering Scopes;
4. resolve TaskSelectionEvidence and TaskContract compatibility when the command is task-relative;
5. verify State Fence, authority and expected current revisions;
6. validate exact canonical provenance/evidence/blob handles;
7. normalize paths/resources and privacy/source visibility;
8. attach instruction taint/origin/disclosure metadata;
9. classify impact and requested semantic effect;
10. normalize freshness against base dependencies and expected post-commit revisions;
11. reject reusable admission that would be stale immediately after its own commit;
12. build deterministic MutationPlan and admission-decision digest;
13. stage the complete immutable operation in ORS/redb;
14. return `ACCEPTED_PENDING` for `accept_after_stage` or wait for the canonical receipt;
15. serialize by Ordering Scope;
16. execute store transaction;
17. reconcile receipt into ORS;
18. dispatch the already committed outbox row.
```

No LLM call occurs in this path.

Freshness is evaluated at an explicit point. A reusable candidate carries a normalized predicate over external/source dependencies and the expected state after its own transition:

```yaml
FreshnessAdmission:
  base_revision_heads:
  expected_post_commit_revision_heads:
  dependency_fence:
  predicate_normal_form:
  disposition: CURRENT | SELF_INVALIDATING | PROJECTION_PENDING |
               EXTERNAL_REVISION_RACE | INCOMPLETE
```

The candidate's own commit increment cannot make it stale by construction. `SELF_INVALIDATING`, unresolved provenance, task mismatch or an external revision race rejects hot/reusable promotion; the safe raw observation may remain cold/quarantined. `WriteReceipt.status=committed` proves durable transport only. It does not prove novelty, freshness, task compatibility, support or verification.

When the canonical candidate is durably committed but its cue/index/context projection has not reached the same source fence, the caller receives `CANDIDATE_COMMITTED_PROJECTION_PENDING`. The record exists and may be fetched by exact handle, but it cannot fire on the hot path or support a Material decision until a `ProjectionPublicationRecord` makes the applicable projection `CURRENT`.

`ACCEPTED_PENDING` proves only that the complete opaque operation was durably staged under the same identity. Normal writer readiness after restart requires ORS enumeration, receipt/store reconciliation and residual-unknown disposition; the status never implies canonical commit or exactly-once external effect.

ORS staging uses a bounded micro-batch only to amortize local transaction/fsync overhead:

```text
first request is flushed immediately under low load;
drain only immediately available operations up to configured item/byte/time cap;
reserve Ordering Scope sequences atomically in one redb transaction;
acknowledge each caller only after that ORS transaction commits;
each PreparedTransition still receives its own canonical transaction and receipt.
```

The micro-batch is an optimization profile, not an ordering or atomicity promise between unrelated operations.

### `PreparedTransition`

`eliotd` produces a deterministic, immutable execution plan after semantic admission:

```yaml
PreparedTransition:
  operation_and_idempotency_identity:
  normalized_semantic_commands:
  mutation_plan_hash:
  principal_session_scope_task:
  ordering_scopes:
  required_authority_and_epoch:
  required_state_fence_and_revisions:
  policy_config_schema_snapshots:
  admission_contract_set_digest:
  proposing_daemon_generation:
  named_store_operation_manifest_digest:
  transition_class: capture_candidate | epistemic | task_control | lifecycle_policy | recovery_schema
  requested_effect_ceiling:
  required_proof_and_approval_refs:
  named_store_operations_and_parameters:
  event_projection_relation_intents:
  receipt_and_outbox_intents:
  privacy_origin_taint_metadata:
```

Kernel does not reinterpret project meaning. It verifies identity, authority, fence, ordering, plan hash, admission/operation-manifest digests, `transition_class`, effect ceiling, required proof/approval handles, allowed named operations and compatibility before staging. A staged plan remains executable after daemon replacement only when the candidate Kernel/store bridge still supports the exact recorded contract/manifests; otherwise it stays staged and enters visible recovery instead of being reinterpreted by newer code. Every named store operation manifest declares the transition classes and maximum epistemic/control effect it may realize. Store bridge rejects a plan whose class, scope or effect exceeds that manifest; it cannot add commands or widen scope. This is a generic hard-boundary check, not a second semantic engine.

