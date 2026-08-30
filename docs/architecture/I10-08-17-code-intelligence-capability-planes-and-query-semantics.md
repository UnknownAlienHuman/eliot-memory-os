### I10.8.17. Code-intelligence capability planes and query semantics

Code intelligence is routed by capability, not by product brand:

```text
source/semantic graph
  exact source, Cargo ownership, definitions/references/implementations;

build/execution/verifier graph
  packages, targets, features/configurations, build scripts, artifacts,
  runners, tests, registered verifiers and coverage edges;

behavioral/history graph
  co-change, churn, hotspots, ownership, fix episodes and drift;

episodic/history projection
  governed Git/session episodes and decision provenance.
```

Each projection is rebuildable and has one selected lifecycle owner for one source/index root. Two always-on watchers over the same root are forbidden outside an explicit comparison experiment.

`QueryIntent` determines stale and assurance semantics:

```yaml
QueryIntent:
  mode: current_position | historical_reconstruction | provenance |
        navigation | verification | change_impact | context_reconstruction
  time_scope:
  branch_environment_scope:
  freshness_policy:
  required_assurance:
```

A stale episode may be valid history and invalid current evidence. A navigation lead may be useful and not evidence.

Result types do not collapse:

```yaml
NavigationCandidate:
  locator:
  why_ranked:
  coverage_state:
  not_evidence: true

EvidenceAtom:
  exact_source_ref:
  exact_anchor:
  observed_scope:
  assurance:

AmbiguitySet:
  query:
  candidates:
  disambiguation_evidence:
  continuation_handles:
```

An unresolved set returns `AMBIGUOUS_RESULT` with all admissible candidates and the cheapest available disambiguation probe. No adapter or Governor projection silently selects the first match.

Coverage/absence is a closed algebra:

```text
complete;
partial;
ambiguous;
stale;
no_index;
no_map;
unknown;
not_applicable.
```

An empty list is never interpreted without this discriminator. Downstream assurance cannot exceed upstream coverage.

`AssuranceCeiling` records:

```text
upstream coverage;
coordinate basis;
approximation kind;
permitted uses;
prohibited uses.
```

Historical/current coordinate conversions are labeled approximate unless exact identity is proven.


Every graph/index query is bound to the canonical `GraphRevisionFence` and publication contract of I5.8. Code-intelligence resolution adds the exact Product/worktree overlay, parser/LSP/build profile, covered relation/configuration scope and reference fallback as dependencies of that fence.

`STALE`, `SPLIT_VIEW`, `FAILED` or unknown coverage cannot prove absence, non-impact or safe deletion. The caller either falls back to exact source/build/verifier evidence, widens the proof tier or returns an explicit unknown.

Scope, authority and disclosure are enforced **before candidate generation and at every structural transformation**, not only when the final packet is rendered. The selection-integrity chain receipt defined in I12.13 covers:

```text
initial source/candidate set;
graph expansion or pivot;
community/cluster selection;
rerank and pruning;
summary/capsule generation;
context compilation;
tool/export delivery.
```

It records admitted and rejected candidates, scope/disclosure closure, transformation lineage and whether untrusted structure changed membership. Unauthorized retrieval, selection-integrity harm and later behavioral contamination are separate outcomes; final-output filtering cannot cleanse an earlier unauthorized selection path.

