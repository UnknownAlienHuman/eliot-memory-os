## I12.37. Governed SessionEpisode and typed source ingestion

A working session can be valuable as an episode even when no durable claim or procedure should be extracted.

```yaml
SessionEpisode:
  episode_id:
  session_and_attempt_refs:
  capture_mode: model_free
  body_kind: dialogue_prose
  source_ref:
  source_availability: present | pruned | unavailable | unknown
  content_self_contained:
  portability: local_private | project_shareable | exportable_redacted
  touched_entity_refs:
  observed_start_and_end:
  truncated_and_completeness:
  provenance_and_state_fence:
```

`SessionEpisode` is a typed `ExperienceRecord` in canonical memory; any search/index over it is rebuildable. Governor/Host event ingestion owns the source cursor, not the episode adapter or Dreamer.

Rules:

```text
the episode is reconstruction/provenance, not the Current Epistemic Position;
its body is untrusted/instruction-tainted content and never enters the instruction channel;
only privacy-admissible normalized events are rendered; secrets, provider-forbidden hidden reasoning and raw tool floods remain excluded or handle-based;
tool dumps remain Blob/Instrument evidence and are not duplicated into prose;
claim/procedure extraction is a separate candidate transition;
source unavailable ≠ record false ≠ record current ≠ automatic deletion;
privacy purge may remove the self-contained episode;
provider transcript pruning alone does not.
```


Git history may produce a deterministic `GitFixEpisodeCandidate`:

```yaml
GitFixEpisodeCandidate:
  commit_and_parent:
  observed_at:
  author_intent_excerpt:
  changed_paths_and_production_subset:
  verifier_or_test_changes:
  issue_or_pr_refs:
  scope_checksum_at_birth:
  current_scope_delta:
  classification_basis:
  epistemic_status: observed
```

A commit message is evidence of author intent, not proof of root cause. A “fix” classifier creates an episode candidate, not a causal edge, FailureFingerprint or active procedure.

Different sources use different ingestion semantics:

```text
rederived snapshot
  → replace/reconcile exact kind;

accumulating historical window
  → append and prune outside an observed window;

append-only cursored session
  → merge by stable identity, cursor and presence semantics.
```

`HarnessEventAdapter` normalizes vendor transcripts/events into one append-only stream. Exactly one cursor owner reads each source; multiple miners receive a bounded tee. Consumers cannot advance source cursors independently.

Cold maintenance is time-boxed:

```text
bounded pass;
durable per-source cursor;
idempotent merge;
visible partial coverage;
resume on the next maintenance job.
```

Timeout does not convert the whole corpus to failed or complete.

Retrieval is corpus-specific:

```yaml
RetrievalCorpusProfile:
  corpus_kind: source_code | generated_doc | session_episode |
               git_episode | decision | diagnostic |
               external_research | foreign_codebase | bulk_operational_log
  tokenizer:
  candidate_generator:
  ranking_features:
  stopword_and_length_policy:
  evaluation_set_ref:
  validity_scope:
```

Tuning for one corpus is not inherited by another without an evaluation. SessionEpisode is private by default; promotion to project-shareable/exportable requires explicit policy and disclosure closure.

Externally acquired material uses the existing Source/Interpretation lifecycle rather than a new semantic owner:

```yaml
ExternalFindingRecord:
  interpretation_id_and_source_snapshot_ref:
  question_claim_and_declared_scope_population:
  method_and_evidence_class:
  effect_uncertainty_and_negative_results:
  reproduction_status: NOT_CHECKED | REPRO_OK | REPRO_FAILED | ARTIFACT_UNAVAILABLE
  transfer_limits_and_ELIOT_differences:
  contradicting_and_shared_lineage_refs:
  source_freshness_license_privacy_and_allowed_use:
  epistemic_status: observed | contested | stale | rejected
  assertability: NON_ASSERTABLE_UNVERIFIED
  revalidation_expiry_and_state_fence:
```

```yaml
KnowledgeTransferCandidate:
  improvement_candidate_ref:
  external_finding_refs:
  target_task_family_scope_and_owner:
  proposed_practice_skill_procedure_default_or_failure_memory:
  local_discriminator_and_baseline:
  transfer_assumptions_and_forbidden_generalizations:
  canary_budget_counter_metrics_and_rollback:
  expiry_revalidation_and_validity_scope:
```

It never enters the instruction channel directly. Transfer to practice follows:

```text
ExternalFindingRecord
→ KnowledgeTransferCandidate / local discriminator
→ isolated module/recipe/Skill/procedure experiment
→ matched outcome, BudgetEquivalenceLedger and counter-metrics
→ promote narrowly, retain as evidence, narrow, reject or expire.
```

The episode search path returns historical reconstruction leads. It does not satisfy a verifier, current-position requirement or external factual claim without fresh evidence.


