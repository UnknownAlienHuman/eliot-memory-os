## I7.17. Convenience surfaces

### Auto-boot

First successful ELIOT response in a Session includes once:

```text
principal/profile identity;
WorkScope and task;
current revisions/freshness;
project/system orientation handles;
critical attention/problems;
actual GovernanceProfile and its limiting IntegrationCoverageProfile evidence.
```

The same state is available as a bounded `GetUnderstandingBootstrap` composition over existing owners. `OnboardingReadinessReceipt` of I4.4.1 is the canonical readiness decision; `UnderstandingBootstrap` is its agent-facing projection plus current cognitive state and cannot report a stronger readiness:

```yaml
UnderstandingBootstrap:
  onboarding_readiness_ref_and_disposition:
  product/workscope identity:
  task_selection: BOUND | UNIQUE | AMBIGUOUS | NONE
  TaskSelectionEvidence:
    scope_level: session | task | project | portfolio
    candidate_task_handles:
    selected_task_and_revision:
    acceptance_digest:
    selection_source_and_reason:
    contamination_flags:
  role/lease and State Fence:
  current assessment: NOT_ONBOARDED | STALE | READY | DEGRADED
  supported/verified/candidate counts:
  bounded relevant handles:
  conflicts/unknowns:
  next safe expansion:
```

Ten open tasks return `AMBIGUOUS`; ELIOT does not silently choose the newest task. A task found only through a previous evaluation candidate is marked `CROSSOVER_CONTAMINATED` until independently rebound.

### Auto-bind

Observation/candidate write derives cues from touched files, symbols, errors, commands, task and active artifacts. Agent supplies only a short reuse note when automatic binding is insufficient.

### Frame stub

`eliot.act` returns a prefilled ActionFrame from current state; the agent supplies intent, expected observable and remaining uncertainty.

### Dry run

Operations with a real validation/simulation capability support `dry_run` with zero side effects and return the normalized envelope plus effect preview. When the external tool cannot safely simulate an effect, ELIOT returns `DRY_RUN_UNSUPPORTED` and the best available static preview; it never pretends that validation occurred.

### Memory confidence

Recall/packet responses return one server-derived `RecallDisposition`:

```text
ADMITTED_STRONG | ADMITTED_WEAK | NO_MATCH | NO_USEFUL_MEMORY |
EMPTY_CORPUS | SCOPE_SUPPRESSED | STALE_PROJECTION |
CONFLICTED | INCOMPLETE_COVERAGE.
```

The receipt binds scope, source/projection revisions, State Fence, visible and suppressed counts, freshness and a short reason. Default agent output contains bounded top handles plus `rank_trace_handle`; full ranking/suppression traces are debug expansions. The agent never invents `NO_USEFUL_MEMORY`.

