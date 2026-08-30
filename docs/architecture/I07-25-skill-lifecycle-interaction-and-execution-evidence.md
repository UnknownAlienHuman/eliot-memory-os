## I7.25. Skill lifecycle, interaction and execution evidence

A Skill is a compact behavioral interface over deeper contracts. It is not considered useful because it is installed, injected or quoted. ELIOT maintains one derived `SkillLifecycleView`:

```yaml
SkillLifecycleView:
  skill_ref_and_revision:
  task_host_route_and_governance_scope:
  applies_when_and_does_not_apply_when:
  dependency_and_tool_definition_versions:
  delivered_expanded_and_executed_counts:
  eligibility_activation_and_activation_latency:
  adherence_at_early_mid_and_final_checkpoints:
  verified_success_failure_and_uncertain_outcomes:
  observed_decision_or_verifier_delta:
  false_activation_and_distractor_history:
  interactions_ordering_and_mutual_exclusion:
  stale_or_quarantine_reason:
  proposed_action: keep | patch | split | merge | suppress | archive | quarantine | restore
  evidence_review_and_rollback:
```

Rules:

```text
installed != delivered != executed != useful;
eligible != activated != adhered: an update may be eligible and never retrieved, retrieved and never used, used early and abandoned by the final turn;
silence about adherence is unknown, not compliance;
retrieval, repetition and model agreement do not reinforce a Skill;
Skill execution is linked to exact steps, artifacts and verifiers when observable;
shared success may remain distributed or uncertain rather than being assigned to one Skill;
where-not-apply, stop and escalation are first-class;
conflicting Skills create an Instruction Conflict and are not resolved by prompt order;
dependency or Tool Definition change marks the Skill stale before Material use;
Dreamer/Curator may propose lifecycle changes, but they remain reversible candidates until governed promotion.
```

A `SkillExecutionEvidence` can show that a procedure was followed and what happened; it cannot prove that the Skill alone caused the result. Per-attempt eligibility, packet position, retrieval, delivery, observable activation and adherence for a Skill/overlay/procedure are bound by the `HarnessActivationReceipt` in I12.24; aggregate lifecycle counts never substitute for that exact receipt. A `SkillInteractionView` records conflicts, required ordering and mutual exclusion only when observed or explicitly specified.

Skill curation is selective and batch-oriented. It examines actual usage, failure, transfer and distractor evidence; it does not rewrite the hot Skill after every task. Low observed utility changes exposure or review priority, not epistemic status or authority.



