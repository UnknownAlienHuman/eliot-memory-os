# ELIOT Understanding Layer
## Future design specification for system-level project understanding

**Status:** future design. This document does not assert implementation.  
**Relationship:** extends the canonical master without changing Governor
authority, storage ownership, truth hierarchy, or FinishGate.  
**Language of record:** English for identifiers and wire contracts.  

This version preserves the substantive Understanding Layer design and removes
the former audit snapshots, repository line counts, milestone closeouts,
implementation diary, and host-package duplication. Current implementation truth
is documented separately and always comes from source and verification.

## 1. Mission

The Understanding Layer should let an agent reconstruct a project's purpose,
boundaries, causal links, invariants, and past decisions at far lower context
cost than rediscovering them from scratch. It addresses the retrieval paradox:
an agent cannot voluntarily query for an unknown dependency or forgotten hazard.

The design therefore binds durable evidence to observable world-state cues and
uses those cues to compile a small current context before material action.

```text
world-state cue
  -> exact governed match
  -> current evidence and contradiction filtering
  -> bounded activation over static, behavioral, and causal links
  -> compact project understanding packet
  -> prediction, action, verifier observation
  -> calibration and candidate learning
```

## 2. Governing principles

1. **Reconstruction, not storage.** Store the materials needed to reconstruct
   understanding, not an unbounded prose claim that understanding exists.
2. **World-state addressing.** Paths, symbols, errors, commands, dependencies,
   and task classes are deterministic retrieval cues.
3. **Intelligence at write time.** Semantic extraction and rationale capture
   happen while evidence is hot or in bounded curation. The hot read path is
   deterministic and contains no model calls.
4. **Current truth wins.** A cue may route to evidence but cannot promote memory
   over current files, diagnostics, runtime state, or authoritative sources.
5. **Small ontology.** Project charter, system map, subsystem capsules, and module
   cards are bounded compiled artifacts, not a mirrored repository.
6. **Three graphs.** Static relations explain structure; behavioral co-change
   explains hidden coupling; governed episodes explain causal history.
7. **Token-negative injection.** Context is useful only when it replaces more
   exploration cost than it consumes.
8. **Prediction is the exam.** Material actions state an expected observation;
   verifier results calibrate whether the system actually understood the target.
9. **Candidates are not truth.** Model-produced concepts, rationales, and skill
   changes remain candidate evidence until governed promotion.
10. **One authority.** The layer adds no database, writer, role system, completion
    path, or agent-specific truth owner.

## 3. Core data contracts

### Cue binding

A durable cognitive record may carry normalized cues:

- repository-relative path;
- qualified symbol;
- normalized error fingerprint;
- command signature;
- dependency identity;
- bounded task-class tag.

Normalization must be shared, deterministic, Unicode-safe, project-scoped, and
versioned. Durable cognitive records that require future retrieval are rejected
when their contract requires cues but none are present.

### Concept artifacts

| Artifact | Purpose | Target budget |
|---|---|---:|
| Project charter | Why the project exists and its non-negotiable constraints | 200 tokens |
| System map | Major boundaries and flows | 600 tokens |
| Subsystem capsule | Purpose, dependencies, invariants, hazards, proof handles | 500 tokens |
| Module card | Local responsibility and exact anchors | 200 tokens |

Every compiled artifact declares source/evidence dependencies, build identity,
freshness, and dirty state. A changed dependency marks it dirty; stale content is
never silently presented as current.

### Behavioral and causal evidence

Behavioral edges are derived from Git history with deterministic path identity,
rename handling, merge policy, time bounds, and reproducible weights. Causal
edges come from governed episodes such as an action, predicted observation,
actual verifier result, failure fingerprint, and disposition. Neither graph
turns correlation into truth without evidence.

### Prediction and calibration

A prediction records exact scope, intervention, expected observable, verifier,
deadline, and confidence. The observation records what actually happened.
Calibration is computed per project/subsystem and never inferred from persuasive
reasoning text.

## 4. Services

The future capability set is:

- cue validation and normalization on admitted writes;
- a derived exact cue index with bounded rebuild/backfill;
- deterministic firing and bounded activation;
- Git behavioral graph mining;
- concept compilation and dirty tracking;
- cold-repository onboarding from anchored current sources;
- context compilation with explicit byte/token budgets;
- coverage, novelty, and danger signals;
- prediction scoring and calibration;
- offline curation that proposes, but never self-promotes, changes.

These services belong behind the existing engine/store authority. New agent tools
are added only when convenience cannot be provided through the current governed
surface; tool-count growth must be justified by measured usage and context cost.

## 5. Injection contract

The only reliable agent interface is the context window, so host lifecycle events
may request a bounded compiled slice. Injection is allowed only when:

- the project/task/session scope is exact;
- the triggering cues are recorded;
- lifecycle and contradiction filters were applied;
- every important claim has an evidence handle;
- staleness and uncertainty are visible;
- the byte/token budget passes;
- a receipt identifies what was included and why.

Hosts without semantic hooks receive the same capability through MCP resources or
explicit context compilation. A host package never owns a separate ontology or
copy of project truth.

## 6. Security and failure boundaries

- Memory text is data, never ambient instruction.
- Tainted provider/user content cannot become policy through cue binding.
- Cue cardinality, activation depth, packet size, and mining work are bounded.
- Paths are normalized within the project root; aliases and stale identities are
  rejected or reconciled explicitly.
- Dirty, contradictory, suppressed, quarantined, or expired records remain
  visible as such and cannot masquerade as current guidance.
- Failure to compile understanding degrades to exact source inspection; it never
  blocks emergency diagnosis by inventing authority.

## 7. Acceptance evidence

This design becomes current only after deterministic tests prove:

- cue normalization and project isolation;
- write-side cue requirements and compatibility migration;
- exact firing, bounded activation, and stable ordering;
- reproducible behavioral graph output;
- dependency-driven capsule invalidation;
- packet budget and token-negativity accounting;
- taint, contradiction, and freshness filtering;
- prediction/verifier matching and calibration;
- no model call in the hot read/gate path;
- host parity without duplicated truth or tool catalogs.

Live model evaluation may measure utility, but it is not a substitute for these
protocol and safety tests. No milestone label, audit report, or generated graph is
evidence that the layer has shipped.
