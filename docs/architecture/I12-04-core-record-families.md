## I12.4. Core record families

Implementation uses a compact set of canonical families, not one table per cognitive metaphor.

```text
SourceRecord       — immutable origin/snapshot/blob lineage;
ObservationRecord  — what a route observed;
Interpretation     — claim/hypothesis/model with support/counterevidence;
AssumptionRecord   — load-bearing assumption with origin, necessity, failure mode and dependents;
DecisionRecord     — chosen action/policy/task decision and rationale;
ExperienceRecord   — episode/action/outcome/failure/procedure candidate;
CommitmentRecord   — future obligation/deadline/trigger;
TaskRecord         — goal/plan/work/finish;
ControlRecord      — attention/problem/conflict/authority/module/job;
ArtifactRecord     — produced or evaluated artifact;
ProjectionRecord   — capsule/graph/index/context manifest;
AuditRecord        — immutable transition/receipt/security history.
```

An assumption is a first-class record because retraction must be mechanical. When an assumption is refuted, its dependents are **withdrawn**, not rewritten: a proposition records under which minimal assumption set it holds, and loses current support when that set fails. This preserves history and makes conflicting contexts coexist without premature consensus.

Typed payloads discriminate subtypes. Storage adapter may use normalized tables/relations, but API stays family-based.

