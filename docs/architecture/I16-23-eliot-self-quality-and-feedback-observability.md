## I16.23. ELIOT self-quality and feedback observability

The Governor/Diagnostic Compiler owns one problem-oriented `EliotSelfQualityView` projection over the SystemObservationJournal, EliotSystemExperienceBank, AgentFeedbackReceipts and product/runtime evidence. Watchdog/Dreamer/Doctor supply observations and candidates; none edits the projection as a second owner:

```yaml
EliotSelfQualityView:
  agent_loop_and_no_progress:
  observation_coverage_and_integration_gaps:
  context_packet_size_quality_and_feedback:
  memory_growth_staleness_duplicates_false_activation_and_use:
  Dreamer_Watchdog_Doctor_job_utility_and_failures:
  configuration_maintenance_and_update_outcomes:
  orphan_descendant_and_unknown_effect_state:
  ProductPulse_and_user_outcome_delta:
  open_problems_improvement_candidates_and_human_actions:
```

Required counter-metrics include:

```text
context bytes/tokens versus acknowledged usefulness and decision delta;
delivered memory versus use, verification and outcome;
candidate/duplicate/stale growth versus resolved knowledge;
agent/tool activity versus evidence/artifact/product progress;
Dreamer/Watchdog agent cost versus accepted diagnosis/repair delta;
maintenance frequency versus recurring failure and operator burden;
feedback resolution latency and repeated wrong-scope/context complaints.
```

The view does not create one global “ELIOT intelligence score.” It identifies concrete failing contours and the next discriminative observation. A persistent self-quality regression creates a Problem or ImprovementCandidate; it does not let Meta silently rewrite the active system.

The closed self-diagnosis loop is explicit and owner-preserving:

```text
ObservationObligationProfile + actual observations/coverage
→ deterministic Signal or quality delta
→ Problem State when persistence/impact requires ownership
→ bounded Dreamer/Watchdog Agent/Doctor diagnosis candidate
→ Human/Main Agent/Governor decision under existing authority
→ repair, configuration candidate, route change, experiment or abstention
→ applicable verifier/Product Pulse and delayed outcome window
→ retain, narrow, rollback, reopen or escalate
→ SystemObservationJournal + EliotSystemExperienceBank writeback.
```

Each loop instance has one governed receipt:

```yaml
SelfQualityInterventionReceipt:
  intervention_id_and_trigger_observation_refs:
  affected_capability_scope_and_owner:
  causal_hypothesis_rivals_and_discriminator:
  selected_action: observe | repair | configure | reroute | experiment | abstain | escalate
  candidate_change_and_authority_refs:
  proof_ceiling_verifier_and_counter_metrics:
  rollback_and_validity_scope:
  immediate_and_delayed_outcomes:
  terminal_disposition: retained | narrowed | rolled_back | reopened | escalated | inconclusive
  system_observation_and_experience_writeback_refs:
```

Recurring failure without a changed hypothesis or discriminator opens Mechanism Review; activity, summary volume or maintenance completion alone cannot close the loop.

### Learning bottleneck diagnosis

One aggregate self-learning score is prohibited. The observed combination locates the bottleneck:

| Observation | Bottleneck |
|---|---|
| update quality high, activation low | retrieval, cue, trigger, or context budget |
| activation high, adherence low | route competence, instruction wording, or state loss between turns |
| adherence high, no decision delta | update irrelevant or too weak |
| decision delta present, outcome worse | bad lesson, bad evaluator, or unresolved confounder |
| immediate gain, retention regression | overfitting and harness-level forgetting |

Diagnosis selects the intervention: change delivery, route, update, evaluator, or roll back.

