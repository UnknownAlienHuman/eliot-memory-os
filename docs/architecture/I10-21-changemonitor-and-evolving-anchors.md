## I10.21. ChangeMonitor and evolving anchors

ChangeMonitor combines host events, filesystem notifications, Git reconciliation, process/tool receipts and artifact scans.

It records:

```text
before/after resources and exact source/artifact revisions;
origin attribution confidence;
associated Session/ActionLease/tool operation/attempt;
unknown-origin changes;
exact diff/artifact/operation handles;
State Fence invalidations.
```

Filesystem notification alone is a hint. Git/content checksum/re-read supplies evidence. Unknown-origin Material mutation blocks governed acceptance until reconciled, but does not crash unrelated modules.

### EvolvingAnchorResolver

The resolver is a deterministic rebuildable projection over immutable original identity, ChangeMonitor observations, VCS/diff history and admitted code-intelligence evidence. It is not a canonical operation store and does not create a second source-history owner.

Resolution order:

```text
original artifact/revision plus existing operation/diff identity;
→ exact file/symbol/AST identity where available;
→ content fingerprint plus structural-neighborhood fingerprint;
→ historical range fallback;
→ explicit resolution status.
```

Status:

```text
exact | moved | modified | ambiguous | stale | deleted | unavailable.
```

Rules:

```text
`ambiguous` never auto-selects the nearest or most similar current fragment;
a deleted target remains addressable as a historical anchor;
text-preserving move/rename may resolve as moved without implying semantic equivalence;
semantic-preserving refactor may make an old review item stale when its requested decision no longer applies;
algorithm/version, inputs, evidence and confidence class are recorded;
false attachment is treated as more harmful than missed automatic resolution;
Human correction produces a new resolver observation, never a rewrite of original history.
```

For public messages/plans/verifier results, immutable revision/span identity is preferred. For source/diff targets, symbol/AST and VCS/diff evidence are used when present. DeltaDB-style character-permalink guarantees are not claimed without an admitted operation/delta substrate that can actually prove them.

`ChangeMonitor`, the resolver and the existing decision/effect/artifact/verifier lineage feed the `ChangeProvenanceView` of I12.10/I12.31. A new durable `CausalChangeOperation` record is introduced only after measured reconstruction failures show that existing operation identities and receipts cannot recover the required boundary; naming convenience is insufficient.

