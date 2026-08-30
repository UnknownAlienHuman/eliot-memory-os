## I7.28. Agent, Human and route feedback contract

ELIOT treats feedback from the working agent as a first-class observation because the route is often the first participant to notice wrong scope, missing context, irrelevant memory, confusing instructions or tool friction. Feedback remains fallible self-report and is correlated with actual packet/tool/outcome evidence before changing policy.

Each significant packet, directive, agent launch and finish surface carries an expiring `feedback_handle`. Feedback uses `eliot.observe { kind: observation }` with the `AgentFeedbackReceipt` subtype; no ninth hot MCP tool is added. The handle routes the record to the `eliot_system` self-scope, so a `wrong_scope` or `scope_ambiguous` complaint is not rejected by the very project binding it challenges. It preserves both claimed and observed scope candidates but has no authority to rebind the project or write its semantic memory.

```yaml
AgentFeedbackReceipt:
  feedback_id_and_handle:
  principal_route_attempt_and_session:
  subject_ref: packet | task | scope | memory_item | instruction | tool | bridge |
               verifier | swarm | maintenance | configuration
  disposition: useful | partly_useful | missing_required_context | wrong_scope |
               stale | contradictory | too_large | too_fragmented | irrelevant |
               instruction_conflict | tool_friction | loop_risk | other
  concise_observation_and_optional_requested_delta:
  public_decision_action_or_failure_ref:
  implicit_telemetry_refs:
  confidence_and_limits:
  state_fence_and_time:
```

```yaml
FeedbackCapabilityProfile:
  route_adapter_and_fingerprint:
  feedback_surfaces: in_band_tool | native_event | result_envelope | post_run_prompt | none
  interruption_and_token_cost:
  correlation_limits_and_blind_intervals:
  supported_subjects_and_max_payload:
  expiry_and_probe_evidence:

FeedbackDispositionReceipt:
  feedback_ref_and_current_state_fence:
  decision: accepted_observation | deduplicated | disputed | needs_evidence |
            current_packet_repaired | scope_revalidation_started |
            queued_meta_candidate | rejected_privacy_or_authority
  immediate_delta_or_recovery_handle:
  durable_problem_or_improvement_ref:
  evidence_needed_and_decision_owner:
  returned_to_route_or_human_at:
```

A route that cannot emit feedback is recorded as `feedback capability unavailable`; its silence is unknown, not satisfaction. For such routes ELIOT may use a result-envelope field or a bounded post-run query, but never fabricates agent approval. Governor/Diagnostic Compiler owns `FeedbackDispositionReceipt`; Scope Resolver, Context Compiler, bridge/tool owner or Meta job may execute the named recovery but cannot rewrite the disposition as a second owner. Accepted feedback receives a disposition visible to the agent/Human when the route supports it, so feedback is not a write-only complaint sink.

Feedback is requested only at useful boundaries—on an explicit problem, after a decision-critical packet, at handoff/finish, or when Watchdog detects drift. Per-turn ratings and mandatory prose are forbidden. Silence means unknown, not satisfaction. Human corrections use the same contract with a Human source class.

`FeedbackSolicitationPolicy` requests one compact disposition only at informative boundaries: first Material packet, substantial truncation/expansion, scope conflict, repeated correction, route handoff, tool failure, finish and a detected no-progress interval. It is suppressed when the same packet/problem has already been rated, when answering would disrupt the task or when expected information value is low.

Feedback may repair the current interaction without waiting for Meta promotion:

```text
wrong_scope / scope_ambiguous
  → freeze dependent context/effects and run ScopeBindingGuard;
missing_required_context
  → offer exact handles or compile a bounded delta;
stale / contradictory
  → revalidate the affected sources/fence and expose the conflict;
too_large / too_fragmented
  → produce a smaller Decision-Safety-Floor-preserving packet;
tool_friction / instruction_conflict
  → return a typed recovery/example and record the observation.
```

These are current-session recovery actions, not proof that the agent’s diagnosis is correct. The feedback path updates the self-scope observation bank, Context/Memory quality projections and, when useful, a bounded Meta/Dreamer diagnostic job. A single complaint does not rewrite ContextRecipe, Skill, route policy or memory. Repeated supported feedback produces a Problem/ImprovementCandidate with exact packet, cost, omission, decision and outcome evidence.

