## I18.43. Agent behavior evaluation

Deterministic runtime correctness and probabilistic agent quality are separate proof systems.

Agent eval corpus includes:

```text
small causal implementation tasks;
wrong-owner and misleading-proxy tasks;
instruction conflict and Recoverable Deviation;
unknown/missing evidence;
repeated failure and Mechanism Review;
blind review and poisoned shared-root cases;
long-horizon resume/reconstruction;
context-size and position variants;
tool/route failure and budget exhaustion.
```

A trial records route fingerprint, packet, tools, actions, artifacts, verification, cost, time and outcome. Metrics include verified task success, unnecessary actions, rule violations, false completion, repeated failures, context use, cost/latency and human attention. Multiple trials estimate a distribution; a model judge is never the sole product verifier.

Every blind trial records:

```text
memory_snapshot_id and immutable namespace/branch;
run order and randomization seed;
prior-run visibility: ISOLATED | CUMULATIVE;
read-set digest, write fence and contamination flags;
allowed Tool/Facet manifest and HostObservedComplianceTrace.
```

Leaderboards use the isolated lane with one frozen oracle. A cumulative lane measures adaptation in a growing shared memory and reports order/crossover effects separately. Tool compliance is derived from host events, not the model's chronological prose.

Eval improvements become RouteOutcomeProfile/Improvement Candidates and do not change policy automatically.

Each release-facing agent/tool surface also runs one **model-stratified usability** profile over the same blind corpus where routes are available and budget-approved:

```text
cheap/flash route;
mid route;
frontier route.
```

Primary observations are scope discovery, exact-handle grounding, stale/wrong-scope rejection, schema first-pass success, same-intent correction recovery, candidate receipt, context tokens and latency. The profile remains `INCOMPLETE` when a stratum is unavailable; a frontier model cannot mask an unusable API for cheaper/common routes, and no fixed vendor/model list is architectural.


The corpus also includes:

```text
memory-function/type ablations where a type-specific benefit is claimed;
first-orientation, first-action, first-safe-action and first-correct-action timing;
HandoffCheckpoint versus equal-token flat summary versus no-context;
Concilium/rival-panel versus single-frame work with anchoring and probe-quality measures;
valid negative-memory near matches, obsolete cases and reopen trials.
```

A typed record family is justified as a policy/representation distinction without ablation, but no type-specific capability or outcome gain is claimed until the corresponding comparison passes. Handoff and panel studies grade constraints, unknowns, safe next action, verifier choice, errors, latency and outcome separately.

The agent/Human surface corpus also includes anchored-review trials:

```text
several independent comments on one long public plan/message/diff;
question, correction, objection, missing-evidence, scope and acceptance items;
original target moved/modified/deleted before response;
requested change outside the commenter or agent authority;
conflicting comments from different authorized principals;
response that answers the surrounding message but omits one item.
```

Measure per-item delivery, answer and final disposition; omission rate; false resolution; time to navigate original/current target and linked change/verifier; unauthorized change attempts; review-token/context cost; and Human correction burden. A batch passes only when every item has an explicit disposition and any unresolved/stale/ambiguous item remains visible.

