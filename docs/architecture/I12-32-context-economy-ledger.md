## I12.32. Context Economy Ledger

Context efficiency is measured without making compactness the objective.

```yaml
ContextEconomyReceipt:
  task_route_profile:
  context_recipe_ref:
  envelope_selection_receipt_ref:
  delivered_payload_and_handle_cost:
  instruction_layer:
    delivered_instruction_directive_and_negative_memory_atoms:
    omitted_atoms_and_reason:
    actual_tokenizer_tokens_and_position:
    instruction_related_failure_or_recovery_refs:
  compilation_stage_costs:
    exact_retrieval:
    optional_retrieval:
    admission_ranking:
    render_omission:
    lint_scorecard_measurement:
    receipt_persistence:
  telemetry_cost:
    CPU_time_wall_time_allocations_bytes_and_IO:
    sampling_profile_and_coverage:
    omitted_measurements_and_reason:
  per_tool_delivery:
    - tool_call_and_result_ref:
      unique_payload_bytes:
      rendered_tokens_by_actual_tokenizer:
      cumulative_replayed_tokens:
      delivery: FULL | PARTIAL | TRUNCATED | MISSING
      expansion_count:
      decision_delta_or_unused:
  cold_orientation_reads_queries_and_expansions:
  time_to_first_safe_material_action:
  reconstruction_or_rehydration_cost:
  missing_context_regret:
  decision_verification_outcome_refs:
  baseline_or_comparison_class:
  net_cost_delta:
```

Rules:

```text
compare within the same task family, route, tools and Governance Profile;
critical context may be token-positive when it prevents material risk;
positive token delta alone does not justify suppression if decision quality improves;
repeated context with no observed decision/proof value creates an Improvement Candidate;
handles-only or layout changes are canary experiments with rollback;
model output tokens are not disguised as orientation savings.

Raw provider events remain step-level evidence: uncached input, cache read/write, text output, exposed reasoning, provider total, component-sum delta, missingness, retry/compaction and billing/context-occupancy semantics are preserved where exposed. Session summaries cannot overwrite those events. Tool schemas/results are attributed separately only under a controlled counterfactual; otherwise they remain part of total prompt/context cost.
```

This preserves the useful UL token ledger while subordinating it to correctness, decision sufficiency and observed outcomes.


The same receipt distinguishes the work stages that a compact-context claim may otherwise hide:

```text
time_to_bounded_orientation;
time_to_first_attempted_action;
time_to_first_safe_material_action;
time_to_first_correct_action;
time_to_first_applicable_verifier_result;
rework after the first action.
```

A `ContextMeasurementEvidence` binds the exact serialized envelope digest, serializer options, actual tokenizer identity/version, actual rendered tokens, estimator identity/value/error, placement/relevance profile and any provider rewrite/truncation. False-safe overflow and false rejection/decomposition are measured separately; an unqualified estimator cannot prove a floor fits.

A claim that selective/compacted context preserves quality requires a predeclared comparison against the safest applicable larger-context or token-matched baseline, a non-inferiority/quality criterion and a separate safety bound. When the Decision Safety Floor cannot be proven under the selected profile, the fallback is an admissible fuller context within the route's safe envelope, decomposition, a safer partial action or abstention—not silent compression.

