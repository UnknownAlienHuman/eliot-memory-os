# Cue projection source instructions

## Purpose and owner boundary

This package is the current consolidated C1 implementation of deterministic,
revision-fenced cue lookup and bounded activation over immutable owner-supplied
records and edges. It owns only the projection value and pure evaluation rules.
It does not own Canonical Memory, admission, lifecycle truth, task selection,
Context influence, retrieval reinforcement, delivery state, or persistence.

Read issue #245 for the local projection-integrity repair and issue #246 before
changing public cue spelling, comparison, row identity, or snapshot closure.
Do not implement the retired function-per-crate prototype directories merely
because historical plans named them. Split this package only after a real
contract, proof, dependency, context, or replacement seam is demonstrated.

## Current public responsibilities

```text
CueKey / ObservedCue
  bounded deterministic normalization and lookup identity;

CueRecord
  immutable target reference plus projection-local lifecycle/freshness state;

CueSnapshot
  one immutable revision/fence-bounded record and activation-edge set;

CueRuntime::fire
  exact/prefix/signature matching plus bounded deterministic activation;

CueSnapshot::invalidate / CueRuntime::invalidated
  pure forward projection revision after an owner-supplied invalidation event.
```

The package is stateless at runtime beyond the immutable `CueSnapshot` value.
No method writes the canonical source records or graph.

## Projection integrity invariants

1. Validate both the supplied cue text and its normalized lookup value. A path
   such as `./` that normalizes to empty is invalid; an empty canonical key must
   never enter lookup or row identity.
2. `Extinguished` is terminal. An explicit deletion or supersession may move any
   non-terminal cue projection row into `Extinguished`; no later transition may
   restore it.
3. Preserve the existing `Archived -> Suppressed` rejection. That transition is
   not reopened as a side effect of fixing deletion/supersession.
4. Every invalidated snapshot uses a strictly newer revision. Two different
   immutable snapshots cannot share one revision identity.
5. Snapshot/source revision checks are projection checks only. They create no
   canonical lifecycle, support, or State-Fence authority.
6. Matching and activation remain deterministic, bounded, side-effect free and
   independent of a model call.
7. Retrieval, firing, repetition, or graph proximity never increases epistemic
   support or memory influence by itself.

## Deferred v2 contract migration

Issue #246 owns the versioned migration for:

```text
lossless canonical/source spelling versus comparison key;
source/platform-qualified case sensitivity;
row identity including CueKind and MatchMode;
duplicate semantic binding and row-ID closure;
activation-edge endpoint/weight/fanout validation;
frozen snapshot denominator and explicit omissions;
v1 replay and compatibility disposition.
```

Do not hide those wire/identity changes in a local integrity patch. Existing v1
bytes, row IDs, traces and consumers require an explicit compatibility and
migration unit.

## Hard boundaries

Do not add:

- a canonical memory or lifecycle writer;
- store, filesystem, process, network, provider, model, or UI dependencies;
- task selection, Context admission, delivery, authority, policy, support, or
  finish decisions;
- retrieval-driven reinforcement;
- unbounded graph traversal or collection growth;
- a new crate without an independent contract/proof/replacement seam;
- automatic GitHub Actions.

Return a ContractChallenge when requested work needs a new public identity,
source-specific comparison policy, another state owner, a canonical transition,
or evidence unavailable inside this package-local unit.

## Proof

Minimum package proof for Rust changes:

```text
cargo fmt --all -- --check
cargo check --locked -p eliot-cues --all-targets
cargo test --locked -p eliot-cues
cargo clippy --locked -p eliot-cues --all-targets -- -D warnings
```

Required integrity fixtures:

```text
normalized-empty key rejection;
Deleted and Superseded move non-terminal rows to Extinguished;
no transition out of Extinguished;
Archived -> Suppressed remains rejected;
next-revision invalidation succeeds;
same/older snapshot revision fails.
```

Package proof establishes only pure projection integrity. Governor cue binding,
canonical projection rebuild, Context admission/use, host delivery and
`D3B_REACTIVE_CONTEXT_PULSE_01` remain separate Edge/Product proofs. Record every
unexecuted boundary exactly.
