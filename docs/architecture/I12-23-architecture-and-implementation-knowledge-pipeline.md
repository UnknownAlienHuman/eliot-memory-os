## I12.23. Architecture and Implementation Knowledge pipeline

ELIOT treats its accepted design books as protected primary self-knowledge with different authority.

```text
Architecture
  defines intent, theory, decision anchors, Hard Boundaries and conflict rationale;
  has semantic precedence over Implementation.

Implementation
  defines the accepted current contracts, owners, protocols, state boundaries,
  DEFAULTs, Research Gates, failure behavior and observable proofs;
  may expose uncertainty or a migration gap but may not silently change intent.
```

Both accepted revisions are registered from exact bytes. Their identity is external to their own contents:

```text
accepted file bytes and BLAKE3/SHA-256 digest;
accepted revision, status and acceptance receipt;
Architecture heading/ARCH anchors and rationale;
Implementation I-section/appendix anchors, contract/default/experiment class,
owner, failure behavior, proof and Research Gate references;
change and supersession history;
dependent code/modules/tests/config/migrations;
invalidated briefs, packets and conformance projections.
```

The accepted Implementation digest is stored in the release/acceptance manifest and canonical source record; it is not self-embedded into the document being hashed.

Pipeline:

```text
Architecture acceptance
→ immutable Architecture SourceRecord
→ deterministic Architecture parser
→ ArchitectureIndex.

Implementation acceptance
→ immutable Implementation SourceRecord
→ deterministic Implementation parser
→ ImplementationIndex.

ArchitectureIndex + ImplementationIndex
→ typed dependency links to modules/contracts/tests/config/migrations
→ current conformance evidence from code/runtime/receipts
→ self-scope Task Understanding and Active Understanding View.
```

Parser output is derived and rebuildable. It never gains more authority than the exact accepted source. At minimum it preserves:

```text
source digest and exact anchor;
statement class and precedence;
owner and affected capability;
state/failure/recovery boundary;
observable proof or explicit Research Gate;
dependency and invalidation set.
```

For any Material change to ELIOT, `eliot.packet` MUST include the applicable Architecture anchors, applicable Implementation contracts/defaults, current support status, known deviations and affected guarantees. The agent does not receive both books wholesale.

Dreamer may produce `ArchitectureBrief`, `ImplementationBrief` or a combined `EliotSelfBrief`. Every brief carries both source digests, exact handles and the precedence boundary. It is a projection, not a new design authority.

Observed code, tests, generated schema, module manifests and runtime behavior are conformance evidence. They cannot replace accepted Architecture or Implementation merely because the running system behaves differently. A mismatch opens a scoped conformance Problem State with four separate possibilities:

```text
implementation defect;
stale or inaccurate Implementation text;
intentional governed deviation/migration gap;
Architecture question requiring Architecture Owner.
```

No automatic repair chooses among those meanings. Main Agent or Human decision authority resolves the issue with evidence and, when necessary, updates the appropriate book through its acceptance path.

