## I12.21. Memory ecology, residual experience and transfer

Memory ecology is evaluated per item and cluster, not only by corpus counts. `MemoryEcologyAssessment` preserves:

```text
retrieval, acknowledgement, verified-use and decision-delta history;
verification success, contradiction, stale-hit and false-activation history;
horizon/checkpoint, expiry/eviction regime and workload/exposure denominators;
representation path: raw episode | typed relation | compiled view | active context;
historical-recall and current-state outcomes separately;
correct | wrong-specific | abstained | unknown outcome classes;
evaluator revision/provenance, comparison/intervention and uncertainty;
context-dominance/gravity and maintenance/storage/curation cost;
minority evidence and unresolved discriminators;
where-applies / where-not-applies and transfer evidence;
negative-transfer, poisoned-influence and suppression history;
obsolete/current/reopen cohorts and valid-near-match positive controls for negative memory;
residual distinctions lost or retained by compression;
recommended keep, narrow, split, compress, suppress, archive, reactivate or review action.
```

Influence is represented as an observable ladder, never one boolean:

```text
stored
→ available
→ delivered
→ acknowledged
→ expanded
→ cited_or_used
→ changed_decision_or_action
→ used_for_verification
→ outcome_supported_or_refuted.
```

The ladder may skip states only when stronger downstream evidence exists. A Delivery Receipt proves only delivery. An acknowledgement proves only receipt. A model statement that memory was useful is candidate evidence until linked to a public decision/action/verifier/outcome. The system may infer use from exact downstream references, but it does not infer hidden thought.

Maintenance reports aggregate these assessments:

```text
candidate backlog;
stale/conflicted/superseded;
cue coverage;
false activations/blocks;
unused context cargo;
negative transfer;
poisoned influence;
missing forgetting;
promotion rate;
Dreamer curation quality;
reconstruction cost and decision quality.
```
Additional first-class capture/binding counter-metrics are:

```text
cold_capture_ratio
  observations captured without a current task binding / all captured observations;

time_to_binding_p50_p95
  elapsed time from cold capture to a governed WorkScope/task/reuse binding;

cold_capture_never_bound
  share still unbound at the declared observation-window end;

binding_rejection_or_rebind_rate
  wrong-scope/ambiguous bindings rejected or later corrected.
```

Dreamer curation may propose candidate bindings for cold observations using source, touched resources, time and later task evidence. Governor/Task owner validates the binding; Dreamer cannot promote support, task control or hot influence. A high cold-capture ratio is an orientation/ingress problem signal, not a reason to discard observations or weaken capture-first.

`MemoryLifecycleEconomicsProfile` measures the whole trajectory rather than only retrieval:

```text
capture/ingest;
read input/output, write and storage by representation path;
semantic construction and reconciliation;
logical rows, file/WAL bytes and device-write evidence separately;
write amplification and storage growth;
source-change → invalidation/revalidation freshness latency;
retrieval, packet, tokenizer/rendering and model-serving cost;
curation, forgetting, purge, rebuild and recovery cost;
wall-clock, tail latency and Human attention;
prevented errors and observed decision/outcome delta;
missing coverage, exclusions and amortization horizon.
```

A local improvement that hides cost in ingestion, background LLM jobs, storage, recovery or Human work is not a net improvement. `MemoryWorkloadProfile`, `MemoryPhaseCostRecord` and `FreshnessLatencySLO` import as projections of this empirical profile; they do not create universal fixed thresholds.

`WeakClaimEcologyProfile` is a scoped diagnostic, not a universal deletion/promotion threshold:

```text
weak_claim_rate = candidate_or_unverified_claims / evaluated_claims;
```

It records denominator, task/route/corpus profile, age and operation mix, evaluator revision, exclusions and uncertainty. A high rate yields `CONTEXT_PROFILE_UNVALIDATED`, `PROBE_REQUIRED` or a curation/evaluation candidate under the applicable profile; it never auto-promotes, auto-deletes or proves that the architecture is bad.

Memory revision/reconsolidation is represented through the existing canonical `MemoryTransition` / `WriteReceipt` owner and a derived `MemoryRevisionEvidence`, not a second memory system:

```yaml
MemoryRevisionEvidence:
  prior_and_new_record_or_model_refs:
  reactivation_trigger_and_task_scope:
  new_observation_outcome_or_prediction_error:
  old_and_new_epistemic_accessibility_and_influence_state:
  retained_narrowed_and_lost_distinctions:
  retrieval_downstream_use_interference_and_false_recall_checks:
  affected_procedures_views_and_dependency_closure:
  rollback_reopen_or_no_return_boundary:
  verifier_or_review_disposition:
```

Raw episodes and source observations remain immutable. Revision changes current support, applicability, accessibility or influence through forward transitions; it cannot rewrite the prior narrative as though it never existed.

Memory-lifecycle proof depth follows effect. A reversible accessibility-only change records a minimal reason, scope, reopen condition and outcome; it does not require the full evaluation below. A Material change to allowed influence requires a scoped `MemoryLifecycleEvaluation`. Physical purge or irreversible/no-return behavior requires the full closure, replica/backup/provider and resurrection checks. The full form is:

```yaml
MemoryLifecycleEvaluation:
  operation: suppress | demote | archive | quarantine | extinguish | physical_purge
  evaluator_kind_and_ground_truth_access:
  corpus_scope_age_operation_mix_and_exposure:
  current_obsolete_context_shift_and_valid_near_match_cohorts:
  false_delete_false_retain_false_block_and_reopen_counts:
  abstention_inconclusive_and_missing_coverage:
  delayed_OOD_and_downstream_noninferiority_or_harm_bound:
  replica_cache_backup_provider_and_disclosure_scope:
  restore_resurrection_and_no_return_test:
  uncertainty_and_terminal_disposition:
```

Rules:

```text
low use never reduces epistemic support by itself;
negative memory and invariants are not suppressed only because they rarely changed an action;
minority/counterevidence remains addressable until its discriminator or applicability is resolved;
procedure or theory transfer requires explicit target scope and local verification;
compression creates an ExperienceCompressionRecord naming sources, retained/lost distinctions, round-trip evidence, cost, revocation behavior and residual handles;
retrieval, repetition and model agreement do not reinforce support automatically;
negative transfer opens review of the source procedure/model and dependent influence closure;
without adequate adjudication, only reversible suppress/quarantine/archive is allowed—destructive purge or permanent extinction cannot claim epistemic safety.
```

Lifecycle changes are proposals unless mechanically reversible, derived and already authorized by policy. Dreamer may prepare the assessment; Governor applies only the allowed transition. One model's delete recommendation is never its own oracle. Proof depth may increase with observed harm or uncertainty, but a low-risk reversible suppression is not turned into a purge-grade ceremony.

