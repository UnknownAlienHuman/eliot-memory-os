## I2.16. Crate size and Agent Context Envelope

### Why LOC is insufficient

An agent breaks a Module not because a crate has a certain line count, but because the following cannot fit together for the change:

```text
goal and invariants;
public contract;
owned state machine;
production source;
relevant tests;
one-hop providers/consumers;
real diagnostics;
position in the product path.
```

Implementation therefore distinguishes three sizes:

```text
Physical Crate Size
  all Human-authored source and ordinary package tests;

Loaded Crate Slice
  production source and focused tests actually loaded in one agent episode;

Agent Workset
  Loaded Crate Slice + module-specific contract, one-hop interfaces,
  FailureFingerprints, diagnostics, and Product Pulse context.
```

A physical crate may exceed one episode only when it contains independently testable internal cells and the loaded slice is demonstrably complete. Arbitrary file chunking is not completeness.

### Deterministic estimate

```text
STU (Source Token Unit) = ceil(UTF-8 bytes / 3)
```

STU is a conservative fallback estimate for planning Rust and Markdown source. When the exact route tokenizer is available, use it; quality curves live in the Effective Context Profile.

### Candidate envelopes and selection rule

ELIOT does not plan ordinary implementation work against a provider's nominal maximum. The `100k`, `130k`, and `150k` bands below are reference candidate profiles, not a closed list or one universal starting band. An installation may qualify smaller or intermediate bands when exact route evidence supports them. Planner selects the **smallest `QUALIFIED_FOR_PROFILE` envelope** that contains the Decision Safety Floor, governing instructions, advertised tool surface, evidence and diagnostics, protected reasoning and review reserve, and the complete causal workset. If no band is qualified yet, selection remains provisional and exposes uncertainty; nominal route size is not grounds to choose the largest envelope or split a Module automatically.

Reference allocation:

| Total active context | system/tools | task/Architecture/contracts | evidence/diagnostics | reasoning/edit/review reserve | margin | primary source + focused tests |
|---:|---:|---:|---:|---:|---:|---:|
| 100k | 18k | 18k | 7k | 25k | 8k | ≈24k |
| 130k | 18k | 22k | 8k | 35k | 12k | ≈35k |
| 150k | 20k | 24k | 10k | 40k | 13k | ≈43k |

This is a planning profile, not a promise of uniform model usability. Tool output, history growth, and failed attempts consume the same envelope; source allowance is not prefilled to its limit.

```yaml
ContextEnvelopeSelectionReceipt:
  task_route_and_impact_profile:
  selected_effective_context_profile:
  selected_candidate_band:
  decision_safety_floor_tokens:
  instruction_and_directive_tokens:
  tool_surface_tokens:
  evidence_and_diagnostic_tokens:
  protected_reasoning_review_and_margin:
  loaded_source_and_test_slice:
  rejected_smaller_and_larger_bands_with_reason:
  qualification_status_and_uncertainty:
  actual_serialized_measurement_ref:
```

The receipt prevents a planning number from becoming an invisible law. A larger band is selected only when a smaller qualified band cannot carry the decision-sufficient workset or when a controlled experiment demonstrates better outcome without unacceptable distraction, latency or cost.

```text
100k route
  one narrow crate or cell; Loaded Crate Slice target 20–30k STU;

130k route
  normal mode; Loaded Crate Slice target 30–45k STU;

150k route
  upper normal mode; Loaded Crate Slice target 35–50k STU;

>180k
  explicit route experiment, cross-crate integration or reconstruction episode;

250k+
  never the default implementation mode merely because of nominal capacity.
```

### Route-specific Agent Workset

`Agent Workset` includes the task, contract, and evidence portion specific to the Module and is therefore larger than one source slice. Its ceiling derives from the total envelope, not one number for all routes.

| Total active context | Workset target | Upper review band | Remaining protected reserve |
|---:|---:|---:|---:|
| 100k | 45–55k STU | 65k STU | system/tools + >=25k reasoning/review + margin |
| 130k | 60–75k STU | 90k STU | system/tools + >=30k reasoning/review + margin |
| 150k | 70–90k STU | 105k STU | system/tools + >=35k reasoning/review + margin |

Exceeding the upper review band is an observation, not an independent prohibition or mandatory ceremony trigger. `ContextScaleReview` opens only when size coincides with an incomplete causal workset, lost edges, insufficient reasoning or review reserve, repeated agent error, unacceptable cost, or Product-Pulse degradation. Planner then considers contract, Module, or Edge decomposition; a more exact projection; or another qualified route. Task Controller may retain a cohesive work unit when the Decision Safety Floor, one-hop effects, verifier, and review reserve fit under the exact tokenizer profile and Product Pulse and counter-metrics show no degradation. That decision remains scoped evidence, not a new permanent Default.

### Physical crate size profiles

Count Human-authored production source and ordinary tests. Generated code, large golden corpora, vendor source, and raw fixtures have separate profiles and are not loaded in full.

| Crate class | Starting target | Review band | Legacy high-review band |
|---|---:|---:|---:|
| primitives/contracts | 5–15k STU | 25k | 40k |
| low-level hot-path primitive | 15–30k | 40k | 60k |
| pure component/domain core | 20–40k | 55–60k | 80k |
| control/service implementation | 30–50k | 70k | 100k |
| adapter/parser/bridge library | 5–20k | 30k | 45k |
| facade/composition/binary | 5–15k | 25k | 40k |
| shared test-support | 10–30k | 45k | 70k |

`Legacy high-review band` exists only for migration and is not a target for new code. All ranges are Empirical Profiles. Crossing a numeric band alone records profile evidence; `CrateScaleReview` becomes active only when a representative task must load an unsafe or incomplete slice, proof, build, or fan-out cost degrades, ownership becomes ambiguous, or agent or Product-Pulse outcomes regress. An unqualified full-crate task may be withheld from automatic scheduling, but the crate is neither failed nor split by size. Cohesion, edge cost, public-contract quality, independently selectable cells, and measured outcomes decide. A cohesive control crate may remain physically larger than one Loaded Slice when the actual workset is complete and independently provable.

For rough orientation using fallback `bytes/3`: 5k STU ≈ 15 KiB UTF-8 source, 12k ≈ 36 KiB, 25k ≈ 75 KiB, 35k ≈ 105 KiB, 60k ≈ 180 KiB. LOC is intentionally not normalized: generated formatting, comments, schemas, and test style produce very different bytes per line.

Crate size is not evaluated apart from change closure. A small contract hub with huge reverse fan-out may cost more than a large leaf crate; a large service crate may remain temporarily when an agent can see independently testable internal cells and extraction would still increase risk.

### Mandatory context around a local change

Even a small crate cannot be assigned to an agent without semantic context. The workset always contains:

```text
Product Objective / causal property;
crate purpose and invariants;
public contract digest;
owned state/effects;
one-hop producers and consumers;
relevant FailureFingerprints;
affected edge tests;
smallest Product Pulse;
explicit non-goals.
```

This prevents optimization of a local expression at the expense of Architecture.

### Qualification of context and crate profiles

Every numeric envelope in I2, I7, I14, I18 and Appendices C/O is an `EmpiricalParameter`, not a universal limit:

```yaml
EmpiricalParameter:
  parameter_id:
  candidate_value_and_units:
  status: UNVALIDATED | OBSERVED | QUALIFIED_FOR_PROFILE | STALE | REJECTED
  profile: {hardware, os, model, route, tokenizer, serializer, task_family, risk_class}
  experiment_and_baseline_refs:
  distribution_and_uncertainty_refs:
  counter_metrics:
  expiry_and_invalidation:
  kill_condition:
```

`UNVALIDATED` values guide planning only. They cannot by themselves block a Material/Critical action, certify a route, force a crate split or justify product acceptance. Crossing a planning ceiling triggers decomposition/review or a profiled experiment; it is not an Architecture violation.


### Exact serialized-context measurement

Context admission and profile qualification use the exact bytes that the selected route will receive, not an abstract source estimate:

```yaml
SerializedContextMeasurement:
  envelope_digest:
  serializer_id_version_and_options:
  route_model_and_actual_tokenizer_id_version_hash:
  rendered_bytes:
  actual_tokens:
  estimator_id_version_and_estimate:
  absolute_and_relative_error:
  false_safe_overflow:
  false_reject_or_unnecessary_decomposition:
  truncation_or_provider_rewrite_evidence:
  placement_and_relevance_profile:
  validity_scope_and_invalidation:
```

`STU`, byte ratios and historical token averages are planning fallbacks only. They never prove that a Decision Safety Floor fits, never authorize truncation and never force a Module split by themselves. An estimator is `QUALIFIED_FOR_PROFILE` only after measuring both dangerous directions: false-safe overflow/truncation and false rejection/decomposition. Any change to route, tokenizer, serializer, tool surface or provider rewrite behavior invalidates the qualification.

