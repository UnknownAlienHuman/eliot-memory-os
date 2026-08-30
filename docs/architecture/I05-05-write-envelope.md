## I5.5. Write envelope

```yaml
CanonicalWriteEnvelope:
  protocol_version:
  write_intent_id:       # stable user/agent intent across typed correction attempts
  operation_id:
  idempotency_key:
  principal:
  session_id:
  scope_id:
  scope_level: session | task | project | portfolio | system
  task_id:
  task_binding_evidence_ref:
  ordering_scopes:      # one or more; complete set declared before staging
  state_fence:
  authority:
  impact_class:
  semantic_commands:
  canonical_provenance_handles:
  evidence_handles:
  blob_handles:
  origin_assurance:
  instruction_taint:
  privacy_class:
  base_dependency_revisions:
  expected_post_commit_revisions:
  freshness_predicate:
  expected_revisions:
  conflict_policy:
  response_mode: wait_for_commit | accept_after_stage
```

An agent-provided semantic label is only a proposal. Governor may reduce the requested epistemic effect, but never discards the original observation. `operation_id` is globally unique within the installation. `idempotency_key` identifies the same logical transition across retries: the same key with the same canonical request hash resolves to the same submission and receipt; the same key with a different hash is rejected as an identity conflict.

One envelope belongs to one WorkScope and one atomic semantic transition. Multiple commands or batch items are allowed only when they share the same causal intent, authority, privacy boundary and complete `ordering_scopes` set. The envelope commits or rejects as a unit. Cross-WorkScope atomic writes, hidden partial success and a command that silently creates a second transition are forbidden.

Task binding and capture are deliberately separated:

```text
`eliot.observe`
  may preserve a safe raw observation as a cold `ObservationCandidate`
  when task selection is absent or ambiguous;

reusable task memory, Claim/Failure/Procedure promotion and task-control writes
  require current `TaskSelectionEvidence`, exact TaskContract revision,
  acceptance digest, WorkScope, State Fence and compatibility disposition;

wrong-scope or incompatible task binding
  rejects the reusable/task-bound transition with `TASK_SELECTION_REQUIRED`
  or `TASK_SCOPE_INCOMPATIBLE`;
  it never silently selects the most recent/open task.
```

A cold unbound capture has no task-specific activation, no support/influence promotion and no finish relevance until a later governed binding transition. This preserves capture-first behavior without recreating the wrong-task contamination observed in the old testbed.

`canonical_provenance_handles` are immutable exact handles. Abbreviated IDs, display labels, prose citations or resolver guesses may be shown in UI, but they cannot satisfy source, evidence, verifier, dependency or authority fields.

### Response modes

```text
wait_for_commit
  wait for canonical WriteReceipt until caller deadline;

accept_after_stage
  return only after complete ORS staging; caller polls/subscribes and MUST NOT retry;

internal_fire_and_observe
  maintenance/system-only service option, not an agent envelope value; no interactive waiter, operation remains fully receipted.
```

If `wait_for_commit` exceeds its deadline after durable staging, the actual result becomes `ACCEPTED_PENDING` with the same operation identity. Request mode and observed result are different fields; a timeout never fabricates rollback or duplicates the write.

