## I12.10. CodeCortex implementation

`CodeCortexService` is a deterministic **task-relative evidence compositor**. It owns no universal graph, tool process, parser or truth. It consumes admitted Instrument Plane evidence and canonical ELIOT state.

Input stack:

```text
TaskContract, acceptance, current plan and WorkScope;
exact Git/base/candidate/worktree identity;
changed paths and owning Cargo packages;
full Cargo package/target/feature/reverse-dependency graph;
rust-analyzer/SCIP definitions, references and implementations;
latest compiler/test/runtime InstrumentRuns;
optional heuristic graph observations with explicit limitations;
ELIOT decisions, invariants, FailureFingerprints, artifacts and verifier map.
```

Output is a bounded `CodeCortexReport` whose every relation carries:

```text
relation kind and endpoints;
evidence authority;
freshness;
coverage;
optional confidence only for heuristic evidence;
source handle and dependency set;
conflicts/unknowns.
```

Report sections:

```text
task entrypoints and exact anchors;
ChangeProvenanceView linking public decisions, attempts, operations, diffs, reviews, historical/current anchors and verifiers;
changed symbols and owning packages;
reverse package and public-symbol impact;
references/implementations and candidate call paths;
relevant test inventory and verifier handles;
architecture/concept boundaries and declared invariants;
known failures and prior decisions;
source disagreements;
coverage gaps and cheapest probes;
handles for expansion.
```

Blast radius is a provenance-preserving union, not a set of text matches:

```text
changed files
+ owning packages
+ reverse package dependencies
+ semantic references to changed public symbols
+ tests covering affected packages/symbols
+ heuristic cross-service candidates.
```

Each reason remains separate. Missing CodeCortex discovery never denies an authorized Add/Modify/Delete/Rename; write authority comes from TaskContract, ActionScope and leases. For a new file, graph coverage may be `not_applicable` or `unknown`, not `file_outside_report`.

`ChangeProvenanceView` is a rebuildable bidirectional projection over existing owners:

```text
request/public message/plan/rationale
→ attempt, action, tool and effect identities
→ ChangeMonitor diff/artifact observations
→ original and currently resolved anchors
→ AnchoredReviewItems
→ verifier/outcome
→ later supersession or correction;

current file/symbol/range
→ operations/attempts that created or touched it
→ linked public decisions/messages
→ artifacts, reviews and verifiers.
```

Every edge carries attribution `exact | receipt_linked | correlated | ambiguous | unknown`. `correlated` is never rendered as causal proof. Missing or ambiguous links remain visible and cannot be repaired by a model-authored narrative.

CodeCortex does not:

```text
parse Rust with ad-hoc text rules;
run duplicate compiler/test commands;
serve hard-coded invariant cards;
turn heuristic similarity/co-change into causal proof;
hide disagreement between rust-analyzer and heuristic graph;
return confident negative answers from partial/stale indexes;
call Dreamer in the hot compositor path.
```

A model may explain unresolved relations later through Dreamer/Concilium, but the original evidence and conflict remain visible. Material code work needs either a fresh applicable report or explicit unknown hops and Investigation Mode; this is a content requirement, not a separate ceremony.

