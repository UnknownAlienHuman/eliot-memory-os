### I10.8.18. Derived-index reference path, impact directives and source views

Every load-bearing optimized projection has:

```text
an exact or slower reference implementation;
differential agreement tests;
rebuild/repair procedure;
query-plan/index-use assertion where applicable;
visible fallback/degraded state;
no confident empty result on index failure.
```

An optimized index may reduce latency; it cannot become a second truth owner.

The build/test plane materializes two linked derived graphs:

```text
BuildExecutionGraph:
  workspace/package/target/feature/configuration/build-script/artifact/runner;

VerifierCoverageGraph:
  test/verifier → exact artifact/code/property/configuration/time scope.
```

Edges carry source revision, tool/profile generation, coordinate basis, coverage and assurance. Filename-pattern guesses are separate from coverage evidence. `no_map` means unknown and triggers broader verification according to policy.

Agent-facing change analysis prefers directives over a composite score:

```yaml
ChangeImpactDirective:
  structural_breaks:
  behavioral_drift_candidates:
  missing_expected_cochanges:
  impacted_verifiers_exact:
  missing_tests:
  unknown_coverage:
  required_broader_profile:
  evidence_refs:
```

`will_break` requires structural/contract evidence. Co-change can only say `may drift`.

Any graph-assisted development/evaluation result preserves one bounded use trace inside existing code-intelligence receipts:

```text
graph composition/definition/source fence;
advertised → eligible → called → delivered → observably used;
first exact source read, first edit boundary and first verifier;
no-graph/exact-reference baseline where benefit is claimed;
total tokens/cache/latency and additional process/index cost;
clean→stale and pass→fail harm, ambiguous/unknown/no-map outcomes;
paired artifact/verifier result and scoped ablation status.
```

Graph benefit is scoped to the exact composition/profile. `ABLATION_SUPPORTED` does not make graph output truth or understanding. A stale-edge fault corpus must include wrong-action and missed-impact cases; publication is blocked by the `GraphRevisionFence` defined in I5.8.

Task-shaped code views support batch targets with per-target isolation:

```text
successful;
failed;
cancelled;
stale;
ambiguous;
omitted;
shared State Fence.
```

`SourceSkeleton` is a navigation projection:

```text
imports;
all signatures/declarations;
selected exact bodies;
line-numbered omitted ranges;
selection trace;
source checksum/parser generation/freshness.
```

Before a broad edit, the agent receives a full-read or AST-aware-edit requirement when the skeleton does not prove sufficient coverage.

Analysis depth is adaptive:

```text
high danger/centrality/recent demand
  → deeper analysis and shorter freshness objective;

stable peripheral code
  → cheap card/handle.
```

Depth never raises epistemic status.

Cross-repository work is limited initially to contract/conformance diagnostics:

```text
unmatched consumer/provider;
weak or inferred integration;
incompatible contract change;
orphan implementation;
Architecture/Implementation conformance gap.
```

A generic global map/dashboard remains optional.


Projection maintenance uses the canonical `ProjectionMaintenanceDecision` of I5.8. For code-intelligence projections its measured inputs include the whole dependency-DAG cost, changed/rewritten fraction, logical and storage write amplification where observable, tail latency, source churn, same-fence equality oracle, reference fallback and rollback plan. Incremental work is never presumed cheaper merely because fewer source rows changed.

A delta candidate that fails the equality oracle, loses dependency lineage or produces a split view is discarded and rebuilt from the reference path. The active graph generation never mixes data from one fence with provenance from another.

Graph value is measured against a matched exact/no-graph baseline. The evaluation records total graph construction/query/context cost, actual advertisement→call→use, first source read/edit, first verifier, stale-edge actions and pass→fail harm. A graph arm may improve navigation while remaining unqualified for causal, absence or authorization claims.

