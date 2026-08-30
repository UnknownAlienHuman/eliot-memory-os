## I12.28. Concept and behavioral build artifacts

Concept Pyramid artifacts are versioned derived records:

```text
Project Charter;
System Map;
Subsystem Capsule;
Module/Workflow Card;
Architecture Brief;
Implementation Brief.
```

Each has:

```text
fixed purpose/section contract;
source/dependency manifest;
exact anchors;
budget profile;
fresh/dirty/stale state;
build receipt;
supersession chain.
```

Compilation pipeline:

```text
1. seed boundaries from manifests/directories/static graph and behavioral clusters;
2. create total file/artifact → concept mapping; unresolved items enter `_unassigned`;
3. fill entrypoints, invariants, dangers, decisions and verifiers deterministically;
4. ask Dreamer/model only for bounded purpose/boundary synthesis when needed;
5. validate every load-bearing sentence against handles and scope;
6. publish as derived projection with dependency manifest and build receipt;
7. mark dirty from outbox dependency changes and rebuild asynchronously;
8. Requester/WorkScope Owner may supersede, rename or split within authority; deterministic onboarding itself does not wait for a preference decision.
```

Deterministic sections are filled from graphs/records. Model jobs write only semantic synthesis that cannot be derived mechanically. Invalid anchors or excessive loss prevent publication; a deterministic degraded fallback keeps onboarding moving. Publication of a derived projection never upgrades the underlying claims.


Decision/capsule freshness also records dependency drift separately from truth status:

```yaml
DependencyDriftObservation:
  subject_ref:
  dependency_set_at_birth:
  changed_dependency_refs:
  changed_fraction_or_structural_delta:
  source_and_current_fences:
  interpretation: unchanged | review_required | incompatible | unknown
  evidence_refs:
```

A changed dependency set does not by itself contradict or supersede a decision. It raises a revalidation obligation. A hotspot or central component lacking rationale, invariant, verifier or current owner creates a `ConformanceGap`; it does not become a model-generated explanation.

Behavioral graph jobs retain:

```text
co-change support/confidence;
hotspot/churn/failure density;
mining window and classifier version;
static-edge existence;
run receipt and head commit.
```

Correlation remains correlation.

