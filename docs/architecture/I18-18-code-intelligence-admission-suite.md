## I18.18. Code-intelligence admission suite

No graph backend is admitted by README or demo. ELIOT maintains a Rust golden repository corpus covering:

```text
free/inherent/trait/generic methods;
associated types/constants;
async items;
macro_rules and proc-macro/derive behavior;
cfg(windows) and feature-gated items;
cross-crate references and re-exports;
build-script generated code;
unit/integration tests;
new/deleted/renamed/case-only files;
non-ASCII Windows paths;
dirty and multiple worktrees.
```

Freshness/failure cases:

```text
edit/new/delete after index;
process killed mid-update;
corrupt/truncated index;
stale long-lived session;
wrong worktree/base/candidate;
empty result from partial coverage;
resource limit exceeded;
cache lock/recovery failure.
```

Compare manual source/Git fixture truth, Cargo metadata, rust-analyzer/SCIP and optional heuristic graph. Measure definition/reference/implementation precision/recall, stale false negatives, negative-answer correctness, worktree identity, time/memory and cleanup.

A heuristic backend is rejected as default if it silently serves stale/incomplete data, emits unqualified empty negatives, selects wrong worktree, leaks processes/locks, breaches resources or cannot bind to exact candidate. It may remain an explicit manual heuristic scout.


Additional graph/projection falsifiers:

```text
exact cue/navigation with all graph edges removed;
GraphRevisionFence mismatch and split-view publication;
stale-edge action that would pass on clean source and fail on stale graph;
scope/disclosure violation introduced at pivot/rerank/community/summary/export;
matched exact/no-graph arm with total construction/query/context cost and outcome;
FULL versus DELTA projection at one source fence with equality oracle;
logical-row versus file/WAL/device-write accounting;
source/reference fallback after index kill or corrupt publication.
```

Graph utility, adoption and latency are reported separately from factual/causal assurance. A graph can be useful and still be unqualified to prove absence, impact or understanding.

### Anchor durability and provenance falsification

The same corpus carries original review/message/diff anchors through:

```text
insertions and formatting;
symbol rename;
function and file move;
rebase/cherry-pick;
semantic-preserving refactor;
semantic-changing refactor;
deletion;
duplicate or near-duplicate blocks;
partial/stale index and missing VCS history.
```

Measure exact/moved/modified resolution, false attachment, correct ambiguous/stale/deleted detection, Human correction rate, latency and evidence cost. False attachment is the critical failure: at uncertainty the resolver must return `ambiguous`/`unavailable`, preserve the historical anchor and refuse silent nearest-match attachment.

`ChangeProvenanceView` tests inject missing and conflicting operation/diff/receipt links. The view must label them `correlated`, `ambiguous` or `unknown`, preserve both directions of navigation where evidence exists and never convert temporal proximity into a causal claim.

